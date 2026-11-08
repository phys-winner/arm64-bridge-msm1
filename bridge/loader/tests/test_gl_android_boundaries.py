"""Source guards for the GL/Android boundary fixes; no NDK or device required.

Texture span arithmetic also has compile-time assertions in the C++ source.
This does not substitute for executing the thunks with a real GL/EGL driver.
"""
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "src"


def thunk(source, name):
    return source.split(f'RegisterThunk("{name}",', 1)[1].split("\n    });", 1)[0]


def main():
    gl = (ROOT / "thunks_gl.cpp").read_text(encoding="utf-8")
    core = (ROOT / "thunks_gl_gles2_core.cpp").read_text(encoding="utf-8")
    android = (ROOT / "thunks_android.cpp").read_text(encoding="utf-8")
    jni = (ROOT / "jni_bridge.cpp").read_text(encoding="utf-8")
    resume = jni.split("static void Native_nativeResume(", 1)[1].split("\n}", 1)[0]
    assert "Call(env, cls, g_symbols.nativeResume)" in resume
    assert "MemoryWrite" not in resume, "The guest resume transition must unpause/unmute its SoundSystem"

    for source in (gl, core):
        for statement in source.split(";"):
            assert len(re.findall(r"args\.(?:F32|I32|U32|Ptr)\(\)", statement)) <= 1, statement
    assert re.findall(r"const GLfloat (\w+) = args.F32\(\);", thunk(gl, "glOrthof")) == [
        "left", "right", "bottom", "top", "near_value", "far_value"
    ]
    assert re.findall(r"const GLfloat (\w+) = args.F32\(\);", thunk(core, "glDepthRangef")) == [
        "near_value", "far_value"
    ]
    assert "GetGlStateValueCount" in thunk(gl, "glGetBooleanv")
    assert "GetGlStateValueCount" in thunk(core, "glGetFloatv")

    compile_shader = thunk(gl, "glCompileShader")
    assert "extension 'GL_EXT_shadow_samplers' is not supported" in compile_shader
    assert 'HasGlExtension(extensions, "GL_OES_depth_texture")' in compile_shader
    assert "RewriteDirectionalLightShadowHigh" in compile_shader
    assert "kDirectionalLightShadowHighSourceLength = 1797" in gl
    assert "kDirectionalLightShadowHighFnv1a64 = 0x8C8CF6E73DC808E8ULL" in gl
    assert "#define ttShadow2D(s,c) step(clamp((c).z,0.0,1.0),texture2D(s,(c).xy).r)" in gl
    assert 'rewritten.find("sampler2DShadow") == std::string::npos' in gl
    assert 'rewritten.find("shadow2DEXT") == std::string::npos' in gl

    for source, name in ((gl, "glTexParameteriv"), (core, "glTexParameterfv"),
                         (core, "glGetTexParameteriv"), (core, "glGetTexParameterfv")):
        assert "GL_TEXTURE_CROP_RECT_OES ? 4 : 1" in thunk(source, name)
    upload = thunk(core, "glTexSubImage2D")
    assert "glGetIntegerv(GL_UNPACK_ALIGNMENT, &unpack_alignment)" in upload
    assert "TextureByteCount(width, height, format, type, unpack_alignment)" in upload
    assert "width > 0 && height > 0 && !pixels" in upload
    assert "row_stride * static_cast<uint64_t>(height - 1) + row_bytes" in core
    assert "static_assert(TextureByteCount(1, 2, GL_RGB, GL_UNSIGNED_BYTE, 4) == 7)" in core

    assert "GuestSpan(" in thunk(android, "AAsset_read")
    lookup = thunk(android, "eglGetProcAddress")
    assert "GuestString(" in lookup and "ProviderKind::Function" in lookup
    assert "GetThunkSymbolTable" not in lookup
    for name in ("eglChooseConfig", "eglCreateContext", "eglCreateWindowSurface"):
        assert "GuestEglInts(" in thunk(android, name)
        assert "&& !attributes" in thunk(android, name)
    for name in ("eglChooseConfig", "eglGetConfigs"):
        body = thunk(android, name)
        assert "count_out, sizeof(EGLint)" in body
        assert "static_cast<size_t>(capacity) * sizeof(uint32_t)" in body
        assert "std::vector<EGLConfig> found(limit)" in body
        assert body.index("GuestRangeValid") < body.index("std::vector<EGLConfig>")
    unsupported = thunk(gl, "glDrawTexfOES")
    assert "provider-policy: glDrawTexfOES unsupported" in unsupported
    assert "required use blocks graphics acceptance" in unsupported
    assert "errno" not in unsupported
    print("GL/Android source boundary checks: PASS (driver execution not tested)")


if __name__ == "__main__":
    main()
