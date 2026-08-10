# Kotlin String Template Encryption — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `StringConcatFactory` invokedynamic sites (Kotlin templates, Java `+`) into encrypted `StringBuilder` sequences so no plaintext template recipe survives in the plugin's output.

**Architecture:** In `EncryptingMethodVisitor`, add `visitInvokeDynamicInsn` that parses the recipe string, emits a `LocalVariablesSorter`-wrapped `StringBuilder` sequence, and routes every literal segment through the existing encrypted-LDC path (`emitEncryptedLdc`). Switch `transformClass` from `ClassWriter(reader, COMPUTE_MAXS)` to `ClassWriter(COMPUTE_MAXS)` (no reader copy) so ASM prunes dead constant-pool entries — the recipe string and previously-leaked plaintext ldcs vanish from the class entirely, not just from the obfuscated JAR.

**Tech Stack:** Kotlin 2.4.0, ASM 9.7 (asm + asm-commons already deps), JUnit 5 via `kotlin("test")`.

## Global Constraints

- Plugin version `v1.9.20` → `v1.9.21` in `build.gradle.kts`.
- Only touch classes not in the exclusion list (kotlin/, java/, android/, StringDecryptor, key-derived decryptor name).
- All user-facing behavior preserved: stack-neutral rewrite, fail-open on malformed recipes (never throw, never corrupt).
- Conventional Commits for every commit.
- Acceptance bar (set by user): unit tests green, SamsWorld2 obfuscated JAR grep → 0 hits, obfuscated JAR runs without `VerifyError`, then publish v1.9.21 and update all consuming projects.
- Do NOT commit to the plugin repo before local verification passes.

---

### Task 1: Extract `emitEncryptedLdc` shared helper from `visitLdcInsn`

**Files:**
- Modify: `src/main/kotlin/EncryptClassesTask.kt` (`EncryptingMethodVisitor` around lines 227-252)

**Interfaces:**
- Produces: `private fun emitEncryptedLdc(mv: MethodVisitor, value: String)` — emits the exact bytecode that `visitLdcInsn` currently produces for a String: either `LDC(encrypted); INVOKESTATIC decryptorClass.decryptorMethod` or (65535-guard fallback) plain `LDC(value)`. Leaves a `String` on the operand stack.
- Consumes: nothing new (uses existing `key`, `decryptorClass`, `decryptorMethod`, `modifiedUtf8Length`).

- [ ] **Step 1: Refactor `visitLdcInsn` to delegate to the new helper**

```kotlin
override fun visitLdcInsn(value: Any?) {
    if (value !is String) {
        super.visitLdcInsn(value)
        return
    }
    emitEncryptedLdc(mv, value)
}

private fun emitEncryptedLdc(mv: MethodVisitor, value: String) {
    val saltBytes = XorEncryptor.encrypt(value, key)
    val encryptedString = String(saltBytes, Charsets.ISO_8859_1)
    if (modifiedUtf8Length(encryptedString) > 65535) {
        mv.visitLdcInsn(value)
        return
    }
    mv.visitLdcInsn(encryptedString)
    mv.visitMethodInsn(
        INVOKESTATIC,
        decryptorClass,
        decryptorMethod,
        "(Ljava/lang/String;)Ljava/lang/String;",
        false
    )
}
```

- [ ] **Step 2: Extract the pure transform into a companion object (for testability)**

Move the body of `transformClass` plus `EncryptingClassVisitor`/`EncryptingMethodVisitor` into a `companion object` on `EncryptClassesTask` so the task instance and the unit tests share one implementation. Replace the instance method with a delegate:

```kotlin
// inside EncryptClassesTask
private fun transformClass(
    bytes: ByteArray, key: Long,
    decryptorClass: String, decryptorMethod: String
): ByteArray = EncryptClassesTask.transformClass(bytes, key, decryptorClass, decryptorMethod)

companion object {
    internal fun transformClass(
        bytes: ByteArray, key: Long,
        decryptorClass: String, decryptorMethod: String
    ): ByteArray {
        val reader = ClassReader(bytes)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
        reader.accept(EncryptingClassVisitor(writer, key, decryptorClass, decryptorMethod), 0)
        return writer.toByteArray()
    }
}
```

> NOTE: Task 3 replaces the `ClassWriter(reader, ...)` constructor and accept flag. Keep the nested visitor classes inside the companion object.

- [ ] **Step 3: Run existing tests**

Run: `./gradlew test`
Expected: all existing tests PASS (behavior unchanged — pure extraction).

- [ ] **Step 4: Commit**

```bash
git add src/main/kotlin/EncryptClassesTask.kt
git commit -m "refactor: extract emitEncryptedLdc shared helper from visitLdcInsn"
```

---

### Task 2: Add `visitInvokeDynamicInsn` indy → StringBuilder rewrite (copy-mode writer first)

**Files:**
- Modify: `src/main/kotlin/EncryptClassesTask.kt`

**Interfaces:**
- Consumes: `emitEncryptedLdc(mv, String)` from Task 1.
- Produces: `EncryptingMethodVisitor.visitInvokeDynamicInsn(name, descriptor, bsm, vararg bsmArgs)` — rewrites `StringConcatFactory` sites into a stack-neutral `StringBuilder` block. Malformed recipes → `super.visitInvokeDynamicInsn(...)` (fail-open).

- [ ] **Step 1: Implement the indy rewrite (plain literal emission first, no encryption)**

```kotlin
override fun visitInvokeDynamicInsn(
    name: String, descriptor: String, bsm: Handle, vararg bsmArgs: Any?
) {
    if (bsm.owner != "java/lang/invoke/StringConcatFactory" ||
        bsm.name !in setOf("makeConcatWithConstants", "makeConcat")
    ) {
        super.visitInvokeDynamicInsn(name, descriptor, bsm, *bsmArgs)
        return
    }

    val argTypes = Type.getArgumentTypes(descriptor)
    val recipe = when (bsm.name) {
        "makeConcat" -> "\u0001".repeat(argTypes.size)
        else -> bsmArgs.getOrNull(0) as? String ?: return run {
            super.visitInvokeDynamicInsn(name, descriptor, bsm, *bsmArgs)
        }
    }
    val constants = bsmArgs.drop(1)
    val segments = parseRecipe(recipe, argTypes.size, constants.size) ?: return run {
        super.visitInvokeDynamicInsn(name, descriptor, bsm, *bsmArgs)
    }

    // 1. Save args: descriptor order argTypes[0..n-1]; on stack argTypes[n-1] deepest.
    val slots = argTypes.map { sorter.newLocal(it) }
    for (i in argTypes.indices.reversed()) {
        mv.visitVarInsn(argTypes[i].getOpcode(Opcodes.ISTORE), slots[i])
    }

    // 2. StringBuilder
    mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
    mv.visitInsn(Opcodes.DUP)
    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)

    // 3. Segments
    for (seg in segments) when (seg) {
        is Literal -> emitEncryptedLdc(mv, seg.text); emitAppend(mv, "Ljava/lang/String;")
        is Arg -> {
            mv.visitVarInsn(argTypes[seg.index].getOpcode(Opcodes.ILOAD), slots[seg.index])
            emitAppend(mv, appendDescriptorFor(argTypes[seg.index]))
        }
        is Const -> emitEncryptedLdc(mv, String.valueOf(constants[seg.index]))
                    .let { emitAppend(mv, "Ljava/lang/String;") }
    }

    // 4. toString
    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
}
```

- [ ] **Step 2: Add the segment model + parser + append-descriptor helpers**

```kotlin
private sealed class Segment {
    class Literal(val text: String) : Segment()
    class Arg(val index: Int) : Segment()
    class Const(val index: Int) : Segment()
}

private fun parseRecipe(
    recipe: String, argCount: Int, constCount: Int
): List<Segment>? {
    val out = mutableListOf<Segment>()
    val run = StringBuilder()
    var argIdx = 0
    var constIdx = 0
    for (c in recipe) when (c) {
        '\u0001' -> {
            if (run.isNotEmpty()) { out += Segment.Literal(run.toString()); run.setLength(0) }
            out += Segment.Arg(argIdx++)
        }
        '\u0002' -> {
            if (run.isNotEmpty()) { out += Segment.Literal(run.toString()); run.setLength(0) }
            if (constIdx >= constCount) return null
            out += Segment.Const(constIdx++)
        }
        else -> run.append(c)
    }
    if (run.isNotEmpty()) out += Segment.Literal(run.toString())
    return if (argIdx == argCount && constIdx == constCount) out else null
}

private fun appendDescriptorFor(type: Type): String = when (type.sort) {
    Type.INT, Type.BYTE, Type.SHORT -> "(I)Ljava/lang/StringBuilder;"
    Type.LONG -> "(J)Ljava/lang/StringBuilder;"
    Type.FLOAT -> "(F)Ljava/lang/StringBuilder;"
    Type.DOUBLE -> "(D)Ljava/lang/StringBuilder;"
    Type.CHAR -> "(C)Ljava/lang/StringBuilder;"
    Type.BOOLEAN -> "(Z)Ljava/lang/StringBuilder;"
    else -> "(Ljava/lang/Object;)Ljava/lang/StringBuilder;"
}

private fun emitAppend(mv: MethodVisitor, argDesc: String) {
    mv.visitMethodInsn(
        INVOKEVIRTUAL, "java/lang/StringBuilder", "append", argDesc, false
    )
}
```

- [ ] **Step 3: Wire `sorter` (LocalVariablesSorter) into `EncryptingMethodVisitor`**

Add `sorter: LocalVariablesSorter` field. In `EncryptingClassVisitor.visitMethod`, wrap:

```kotlin
override fun visitMethod(
    access: Int, name: String, descriptor: String,
    signature: String?, exceptions: Array<out String>?
): MethodVisitor {
    val sorter = LocalVariablesSorter(access, descriptor, super.visitMethod(access, name, descriptor, signature, exceptions))
    return EncryptingMethodVisitor(sorter, sorter, key, decryptorClass, decryptorMethod)
}
```

- [ ] **Step 4: Compile**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add src/main/kotlin/EncryptClassesTask.kt
git commit -m "feat: rewrite StringConcatFactory indy sites into encrypted StringBuilder blocks"
```

---

### Task 3: Switch to prune-all `ClassWriter(COMPUTE_MAXS)` (no reader copy) + EXPAND_FRAMES

**Files:**
- Modify: `src/main/kotlin/EncryptClassesTask.kt` (`transformClass`, line ~186)

**Interfaces:**
- Consumes: nothing new.
- Produces: `transformClass` now uses `ClassWriter(COMPUTE_MAXS)` without reader, and `reader.accept(..., ClassReader.EXPAND_FRAMES)`. Dead constant-pool entries (the recipe string, previously-leaked plaintext ldc strings) are pruned from the output class.

- [ ] **Step 1: Change the writer construction and accept flag**

```kotlin
private fun transformClass(
    bytes: ByteArray, key: Long,
    decryptorClass: String, decryptorMethod: String
): ByteArray {
    val reader = ClassReader(bytes)
    // NOTE: no reader passed to ClassWriter — ASM then rebuilds the constant pool from
    // references only, pruning dead entries (e.g. the recipe string and old plaintext ldcs).
    val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
    reader.accept(
        EncryptingClassVisitor(writer, key, decryptorClass, decryptorMethod),
        ClassReader.EXPAND_FRAMES   // required by LocalVariablesSorter
    )
    return writer.toByteArray()
}
```

- [ ] **Step 2: Compile**

Run: `./gradlew compileKotlin`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/EncryptClassesTask.kt
git commit -m "refactor: prune dead constant pool entries via non-copy ClassWriter"
```

---

### Task 4: Unit tests for the indy rewrite (JUnit 5)

**Files:**
- Create: `src/test/kotlin/EncryptingMethodVisitorTest.kt`

**Interfaces:**
- Consumes: `EncryptClassesTask.transformClass` (internal companion object from Task 1 Step 2), the real `StringDecryptor` object (on test classpath) with `KEY` settable.
- Produces: reflective assertions that rewritten templates produce the exact plaintext expectation.

- [ ] **Step 1: Confirm the companion object is reachable from tests**

The companion object's `transformClass` is `internal` (Task 1 Step 2), so `src/test` of the same module can call it as `EncryptClassesTask.transformClass(...)`. No further visibility change needed. If the build reports a visibility error, change the companion function (and its nested visitor classes) from `internal` to `@VisibleForTesting`-annotated `internal` — the `internal` keyword is sufficient for same-module tests.

- [ ] **Step 2: Write the test fixture builder + tests**

```kotlin
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.*
import java.lang.reflect.Method

class EncryptingMethodVisitorTest {

    private val key = 0xDEADBEEFCAFEBABEL

    private fun fixture(recipe: String, desc: String, constants: Array<Any?> = emptyArray()): Class<*> {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "Fixture", null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", desc, null, null)
        // stack: args a0..an-1 (n = arg count from desc)
        val argTypes = Type.getArgumentTypes(desc)
        val n = argTypes.size
        for (i in 0 until n) {
            argTypes[i].let { mv.visitVarInsn(it.getOpcode(Opcodes.ILOAD), i) }
        }
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", desc, bsm, recipe, *constants)
        val ret = Type.getReturnType(desc)
        mv.visitInsn(ret.getOpcode(Opcodes.IRETURN))
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()
        val original = cw.toByteArray()

        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(
            original, key, "StringDecryptor", "decrypt"
        )
        assertTrue(!String(transformed, Charsets.ISO_8859_1).contains(recipe))
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "Fixture") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        return loader.loadClass("Fixture")
    }

    private fun invoke(clazz: Class<*>, args: Array<Any?>): Any? {
        val types = Array(args.size) { i -> args[i]!!::class.javaPrimitiveType ?: args[i]!!::class.java }
        return clazz.getMethod("run", *types).invoke(null, *args)
    }

    @Test
    fun `literal plus two String args`() {
        val c = fixture("Hello \u0001 and \u0001", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
        assertEquals("Hello Foo and Bar", invoke(c, arrayOf("Foo", "Bar")))
    }

    @Test
    fun `two args no literal`() {
        val c = fixture("\u0001-\u0001", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;")
        assertEquals("A-B", invoke(c, arrayOf("A", "B")))
    }

    @Test
    fun `int arg`() {
        val c = fixture("count=\u0001", "(I)Ljava/lang/String;")
        assertEquals("count=42", invoke(c, arrayOf(42)))
    }

    @Test
    fun `long arg`() {
        val c = fixture("id=\u0001", "(J)Ljava/lang/String;")
        assertEquals("id=9007199254740993", invoke(c, arrayOf(9007199254740993L)))
    }

    @Test
    fun `recipe with literal newline`() {
        val c = fixture("line1\n\u0001", "(Ljava/lang/String;)Ljava/lang/String;")
        assertEquals("line1\nvalue", invoke(c, arrayOf("value")))
    }

    @Test
    fun `constant segment from bsm arg`() {
        val c = fixture("pre \u0002 \u0001", "(Ljava/lang/String;)Ljava/lang/String;", arrayOf(7))
        assertEquals("pre 7 value", invoke(c, arrayOf("value")))
    }

    @Test
    fun `arg only via makeConcat`() {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "Fixture2", null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(Ljava/lang/String;)Ljava/lang/String;", null, null)
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcat",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;",
            false
        )
        mv.visitInvokeDynamicInsn("makeConcat", "(Ljava/lang/String;)Ljava/lang/String;", bsm)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()
        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "Fixture2") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        val c = loader.loadClass("Fixture2")
        assertEquals("hello", c.getMethod("run", String::class.java).invoke(null, "hello"))
    }

    @Test
    fun `malformed recipe left untouched - no crash`() {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "Fixture3", null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(Ljava/lang/String;)Ljava/lang/String;", null, null)
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/String;)Ljava/lang/String;", bsm, "\u0001 \u0001")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()
        // arg-count mismatch (recipe expects 2 args, desc has 1) → fail-open, no crash
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        assertTrue(transformed.size > 0)
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `./gradlew test`
Expected: all tests PASS (each fixture loads, the method verifies on the JVM, and the output matches plaintext).

- [ ] **Step 4: Commit**

```bash
git add src/test/kotlin/EncryptingMethodVisitorTest.kt src/main/kotlin/EncryptClassesTask.kt
git commit -m "test: cover indy rewrite for templates, primitives, constants, malformed recipes"
```

---

### Task 5: Plugin build + publishToMavenLocal (local verification)

**Files:**
- Modify: `build.gradle.kts` (`version = "v1.9.20"` → `"v1.9.21"`)

**Interfaces:**
- Produces: `com.github.MRZ07:Cryptor-Gradle-Plugin:v1.9.21` in the local Maven repo (available to SamsWorld2 via its `mavenLocal()` repository).

- [ ] **Step 1: Bump the version**

Edit `build.gradle.kts:8`:

```kotlin
version = "v1.9.21"
```

- [ ] **Step 2: Build the plugin and publish to mavenLocal**

Run: `./gradlew publishToMavenLocal`
Expected: BUILD SUCCESSFUL; `~/.m2/repository/com/github/MRZ07/Cryptor-Gradle-Plugin/v1.9.21/` contains the plugin JAR + POM.

- [ ] **Step 3: Commit**

```bash
git add build.gradle.kts
git commit -m "chore: bump version to v1.9.21"
```

---

### Task 6: SamsWorld2 integration — obfuscated JAR smoke test

**Files:**
- Modify (in SamsWorld2 worktree `/Users/RASHEEM/orca/workspaces/SamsWorld2/proguard`):
  - `core/build.gradle`, `ios/build.gradle`, `android/build.gradle`, `lwjgl3/build.gradle` — `version "v1.9.20"` → `"v1.9.21"`

**Interfaces:**
- Consumes: the local `v1.9.21` from mavenLocal (resolved before JitPack due to repository order).
- Produces: an obfuscated fat JAR at `lwjgl3/build/libs/...obf...jar` with zero plaintext template hits.

- [ ] **Step 1: Update the plugin version in SamsWorld2**

In all four build files, change `v1.9.20` → `v1.9.21`.

- [ ] **Step 2: Build the obfuscated JAR**

Run (in the SamsWorld2 worktree):
```bash
./gradlew lwjgl3:proguardJar
```
Expected: BUILD SUCCESSFUL. NOTE: resolve against local mavenLocal `v1.9.21`; if JitPack doesn't have it yet, `mavenLocal()` satisfies the `useModule` remap.

- [ ] **Step 3: Grep the obfuscated JAR for previously-leaked templates**

```bash
cd lwjgl3/build/libs
unzip -p <obfuscated-jar>.jar '*.class' | strings | grep -E 'setGameMap Start:|setGameMap Ende:|Failed to remove disconnected slot|Controller .* generation .* is not current'
```
Expected: no output (0 hits). Also verify no plaintext `SMOKE_` template fragments:
```bash
unzip -p <obfuscated-jar>.jar '*.class' | strings | grep 'SMOKE_' || echo "CLEAN"
```

- [ ] **Step 4: Run the obfuscated JAR as a smoke test**

```bash
java -jar lwjgl3/build/libs/<obfuscated-jar>.jar
```
Expected: game boots to the main screen without `VerifyError` / `NoClassDefFoundError` / `BootstrapMethodError`. Confirm the previously-leaking code paths (e.g. controller profile selection) don't throw. Keep the run short (headless-safe if possible).

- [ ] **Step 5: Commit the SamsWorld2 version bumps**

```bash
git add core/build.gradle ios/build.gradle android/build.gradle lwjgl3/build.gradle
git commit -m "chore: bump Cryptor plugin to v1.9.21"
```
(Only after step 3+4 pass. Do NOT commit yet if verification failed.)

---

### Task 7: Publish plugin v1.9.21 (JitPack) + update all consuming projects

**Files:**
- Plugin repo: push main + tag `v1.9.21`
- All consuming projects: bump the plugin version to `v1.9.21`

**Interfaces:**
- Consumes: green local verification (Tasks 4-6).
- Produces: published `v1.9.21` resolvable via JitPack; every project using the plugin updated.

- [ ] **Step 1: Push the plugin repo and tag**

```bash
cd /Users/RASHEEM/Desktop/Repos/MRZ07/Cryptor-Gradle-Plugin
git push origin main
git tag v1.9.21
git push origin v1.9.21
```
JitPack then builds `v1.9.21` from the tag automatically.

- [ ] **Step 2: Confirm JitPack resolves**

Wait for JitPack build (or trigger via `https://jitpack.io/com/github/MRZ07/Cryptor-Gradle-Plugin/v1.9.21`), then confirm in a consuming project with `./gradlew dependencies` that `v1.9.21` resolves.

- [ ] **Step 3: Update all consuming projects**

For every project referencing `Cryptor-Gradle-Plugin` (SamsWorld2 already bumped in Task 6; find others):
```bash
cd <project>
grep -rl 'Cryptor-Gradle-Plugin.*v1\.9\.20' --include='*.gradle' --include='*.kts' .
# bump each to v1.9.21
```

- [ ] **Step 4: Final acceptance re-run on SamsWorld2 with the JitPack-published version**

In SamsWorld2: `./gradlew lwjgl3:proguardJar` (now resolving v1.9.21 from JitPack, mavenLocal no longer needed), grep again for 0 hits, run the JAR once more.

---

## Self-Review

**Spec coverage:** The design's six verification shapes (literal+arg, two args, arg-only, primitive, `\n`, `\2`-constant, makeConcat, malformed) are all in Task 4's test matrix. The `\n` case: recipe contains a literal `\n` → parser treats it as a literal char (not `\u0001`/`\u0002`), so it lands in a Literal segment — covered. The `\2` constant case is covered. `makeConcat` covered. Integration (obf jar grep + run) in Task 6. Publishing + consumer updates in Task 7. The user's exact reported case (`Controller \u0001 generation \u0001 is not current`) is the literal+two-args shape covered by the first test.

**Placeholder scan:** All code blocks are complete. No TBD/TODO.

**Type consistency:** `emitEncryptedLdc(mv, String)` defined in Task 1 used identically in Task 2. `Segment.Literal/Arg/Const`, `parseRecipe`, `appendDescriptorFor`, `emitAppend` signatures consistent across Task 2. `transformClass` made `internal` in Task 4 and called as `EncryptClassesTask.transformClass(...)`. The visitor constructor gains a `sorter` param — `EncryptingClassVisitor.visitMethod` updated in Task 2 Step 3.

**Gap found during review:** The malformed-recipe test asserts only "no crash" — but fail-open must also preserve the original indy so the class still verifies. The test's recipe `"\u0001 \u0001"` with 1 arg → `argIdx` would be 2 ≠ argCount 1 → `parseRecipe` returns null → original indy kept. The fixture's single `ALOAD 0` provides the 1 arg. Correct as written.
