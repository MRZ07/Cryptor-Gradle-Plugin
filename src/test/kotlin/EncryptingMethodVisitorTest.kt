import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.*
import java.lang.reflect.Method

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
        // arg-count mismatch (recipe expects 2 args, desc has 1) → fail-open, no crash
        val transformed = EncryptClassesTask.transformClass(cw.toByteArray(), key, "StringDecryptor", "decrypt")
        assertTrue(transformed.size > 0)
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
}
