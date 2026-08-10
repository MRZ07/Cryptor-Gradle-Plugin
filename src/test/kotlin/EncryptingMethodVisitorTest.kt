import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.*
import java.io.File

class EncryptingMethodVisitorTest {

    // 0xDEADBEEFCAFEBABEL is a Kotlin compile error (hex literal > Long.MAX_VALUE);
    // -0x2152411035014542L is the identical 64-bit pattern (two's complement).
    private val key = -0x2152411035014542L

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
        // arg-count mismatch (recipe expects 2 args, desc has 1) → fail-open, no crash.
        // The original invokedynamic must survive unchanged: the transform did NOT rewrite the
        // indy away. Verify by checking the StringConcatFactory BSM owner is still referenced
        // (a rewritten site would have replaced it with the StringBuilder block) and the class
        // is still structurally loadable.
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        val text = String(transformed, Charsets.ISO_8859_1)
        assertTrue(text.contains("StringConcatFactory"), "fail-open must keep the original indy (BSM owner still present)")
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "Fixture3") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        val c = loader.loadClass("Fixture3")
        assertEquals(1, c.declaredMethods.size)
    }

    @Test
    fun `rewrite with control flow produces verifiable frames`() {
        // Method with an if/else whose branches both contain templates. This produces
        // StackMapTable frames at the branch targets — the rewrite adds new locals, so
        // the frames MUST be recomputed (COMPUTE_FRAMES) or the class fails verification.
        // Regression test for: VerifyError "Inconsistent stackmap frames" / ProGuard
        // "Value in slot N of type SOME_REFERENCE expected, but found: i".
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "FixtureFrame", null, "java/lang/Object", null)
        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run",
            "(IZ)Ljava/lang/String;", null, null
        )
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        val elseLabel = Label()
        val endLabel = Label()
        mv.visitVarInsn(Opcodes.ILOAD, 1)
        mv.visitJumpInsn(Opcodes.IFEQ, elseLabel)
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(I)Ljava/lang/String;", bsm, "x=\u0001")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitLabel(elseLabel)
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(I)Ljava/lang/String;", bsm, "y=\u0001")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitLabel(endLabel)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()

        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "FixtureFrame") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        val c = loader.loadClass("FixtureFrame")
        val m = c.getMethod("run", Int::class.javaPrimitiveType, Boolean::class.javaPrimitiveType)
        assertEquals("x=42", m.invoke(null, 42, true))
        assertEquals("y=7", m.invoke(null, 7, false))
    }

    @Test
    fun `rewrite inside a loop with pre-existing locals`() {
        // Loop with a template inside. The loop head is a StackMapTable frame target with
        // pre-existing locals (StringBuilder + counter) that LocalVariablesSorter must remap
        // around our new arg-save locals. Regression test for ProGuard's PartialEvaluator
        // "Value in slot N of type SOME_REFERENCE expected, but found: i".
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "FixtureLoop", null, "java/lang/Object", null)
        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run",
            "(ILjava/lang/String;)Ljava/lang/String;", null, null
        )
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)
        mv.visitVarInsn(Opcodes.ASTORE, 3)
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitVarInsn(Opcodes.ISTORE, 4)
        val loopHead = Label()
        val exit = Label()
        mv.visitLabel(loopHead)
        mv.visitVarInsn(Opcodes.ILOAD, 4)
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitJumpInsn(Opcodes.IF_ICMPGE, exit)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitVarInsn(Opcodes.ILOAD, 4)
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/String;I)Ljava/lang/String;", bsm, "\u0001=\u0001;")
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false)
        mv.visitInsn(Opcodes.POP)
        mv.visitIincInsn(4, 1)
        mv.visitJumpInsn(Opcodes.GOTO, loopHead)
        mv.visitLabel(exit)
        mv.visitVarInsn(Opcodes.ALOAD, 3)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()

        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "FixtureLoop") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        val c = loader.loadClass("FixtureLoop")
        val m = c.getMethod("run", Int::class.javaPrimitiveType, String::class.java)
        assertEquals("a=0;a=1;a=2;", m.invoke(null, 3, "a"))
    }

    @Test
    fun `float arg`() {
        val c = fixture("ratio=\u0001", "(F)Ljava/lang/String;")
        assertEquals("ratio=1.5", invoke(c, arrayOf(1.5f)))
    }

    @Test
    fun `double arg`() {
        val c = fixture("val=\u0001", "(D)Ljava/lang/String;")
        assertEquals("val=2.25", invoke(c, arrayOf(2.25)))
    }

    @Test
    fun `boolean arg`() {
        val c = fixture("flag=\u0001", "(Z)Ljava/lang/String;")
        assertEquals("flag=true", invoke(c, arrayOf(true)))
    }

    @Test
    fun `char arg`() {
        val c = fixture("grade=\u0001", "(C)Ljava/lang/String;")
        assertEquals("grade=A", invoke(c, arrayOf('A')))
    }

    @Test
    fun `rewrite inside try catch with exception handler`() {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "FixtureTry", null, "java/lang/Object", null)
        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run",
            "(IZ)Ljava/lang/String;", null, null
        )
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        val start = Label()
        val end = Label()
        val handler = Label()
        mv.visitTryCatchBlock(start, end, handler, "java/lang/ArithmeticException")
        mv.visitLabel(start)
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(I)Ljava/lang/String;", bsm, "v=\u0001")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitLabel(end)
        mv.visitLabel(handler)
        mv.visitLdcInsn("boom")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()

        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "FixtureTry") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        val c = loader.loadClass("FixtureTry")
        val m = c.getMethod("run", Int::class.javaPrimitiveType, Boolean::class.javaPrimitiveType)
        assertEquals("v=99", m.invoke(null, 99, true))
    }

    @Test
    fun `oversized literal falls back to plaintext LDC via 65535 guard`() {
        val big = "x".repeat(40000)
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "FixtureBig", null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()Ljava/lang/String;", null, null)
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "()Ljava/lang/String;", bsm, big)
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()

        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> =
                if (name == "FixtureBig") defineClass(name, transformed, 0, transformed.size)
                else super.findClass(name)
        }
        val c = loader.loadClass("FixtureBig")
        val m = c.getMethod("run")
        assertEquals(big, m.invoke(null))
    }

    // Builds a class named [name] extending [superName] with a no-arg constructor and,
    // when [body] is provided, a public `method()Ljava/lang/String;` whose bytecode is [body].
    private fun buildSimpleClass(
        name: String, superName: String,
        methodBody: ((MethodVisitor) -> Unit)? = null
    ): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, name, null, superName, null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(0, 0)
        init.visitEnd()
        if (methodBody != null) {
            val m = cw.visitMethod(Opcodes.ACC_PUBLIC, "method", "()Ljava/lang/String;", null, null)
            methodBody(m)
            m.visitMaxs(0, 0)
            m.visitEnd()
        }
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun writeClass(name: String, bytes: ByteArray): File {
        val f = File.createTempFile("cls-$name", ".class")
        f.deleteOnExit()
        f.writeBytes(bytes)
        return f
    }

    @Test
    fun `frame merge of two app classes resolves common superclass via hierarchy map`() {
        // Base has method()Ljava/lang/String; returning "AB"; A and B extend Base.
        val baseBytes = buildSimpleClass("Base", "java/lang/Object") { mv ->
            mv.visitLdcInsn("AB")
            mv.visitInsn(Opcodes.ARETURN)
        }
        val aBytes = buildSimpleClass("A", "Base")
        val bBytes = buildSimpleClass("B", "Base")

        // runner: (boolean) -> "tag=" + (flag ? new A() : new B()).method()
        // Fixture frames are built with an Object fallback (A/B aren't loadable here); the
        // transform's COMPUTE_FRAMES then re-derives them via the hierarchy map → Base.
        val cw = object : ClassWriter(ClassWriter.COMPUTE_FRAMES) {
            override fun getCommonSuperClass(type1: String, type2: String): String =
                "java/lang/Object"
        }
        cw.visit(Opcodes.V11, Opcodes.ACC_PUBLIC, "Runner", null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(Z)Ljava/lang/String;", null, null)
        val bsm = Handle(
            Opcodes.H_INVOKESTATIC,
            "java/lang/invoke/StringConcatFactory",
            "makeConcatWithConstants",
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
            false
        )
        val elseL = Label()
        val mergeL = Label()
        mv.visitLdcInsn("tag=")
        mv.visitVarInsn(Opcodes.ILOAD, 0)
        mv.visitJumpInsn(Opcodes.IFEQ, elseL)
        mv.visitTypeInsn(Opcodes.NEW, "A")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "A", "<init>", "()V", false)
        mv.visitJumpInsn(Opcodes.GOTO, mergeL)
        mv.visitLabel(elseL)
        mv.visitTypeInsn(Opcodes.NEW, "B")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "B", "<init>", "()V", false)
        mv.visitLabel(mergeL)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "Base", "method", "()Ljava/lang/String;", false)
        mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", bsm, "\u0001\u0001")
        mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()
        val runnerBytes = cw.toByteArray()

        val hierarchy = EncryptClassesTask.buildHierarchyMap(
            listOf(
                writeClass("Base", baseBytes),
                writeClass("A", aBytes),
                writeClass("B", bBytes),
                writeClass("Runner", runnerBytes),
            )
        )
        assertEquals("Base", hierarchy["A"]?.superName)
        assertEquals("Base", hierarchy["B"]?.superName)

        StringDecryptor.KEY = key
        val transformed = EncryptClassesTask.transformClass(runnerBytes, key, "StringDecryptor", "decrypt", hierarchy)
        val loader = object : ClassLoader() {
            override fun findClass(name: String): Class<*> = when (name) {
                "Base" -> defineClass(name, baseBytes, 0, baseBytes.size)
                "A" -> defineClass(name, aBytes, 0, aBytes.size)
                "B" -> defineClass(name, bBytes, 0, bBytes.size)
                "Runner" -> defineClass(name, transformed, 0, transformed.size)
                else -> super.findClass(name)
            }
        }
        val c = loader.loadClass("Runner")
        val m = c.getMethod("run", Boolean::class.javaPrimitiveType)
        assertEquals("tag=AB", m.invoke(null, true))
        assertEquals("tag=AB", m.invoke(null, false))
    }
}
