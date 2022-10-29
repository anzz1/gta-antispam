workspace "gta-antispam"
   configurations { "Release" }
   platforms { "x64" }
   location "build"
   objdir ("build/obj")
   buildlog ("build/log/%{prj.name}.log")

   characterset ("MBCS")
   staticruntime "Off"
   exceptionhandling "Off"
   floatingpoint "Fast"
   intrinsics "On"
   flags { "NoBufferSecurityCheck", "NoIncrementalLink", "NoManifest", "NoPCH", "NoRuntimeChecks", "OmitDefaultLibrary" }
   buildoptions { "/kernel" }
   linkoptions { "/NODEFAULTLIB", "/SAFESEH:NO", "/EMITPOGOPHASEINFO", "/RELEASE" }

   filter "configurations:Release"
      defines "NDEBUG"
      optimize "Speed"
      symbols "Off"

   filter "platforms:x64"
      architecture "x64"

project "gta-antispam"
   kind "SharedLib"
   language "C"
   targetname "antispam"
   targetextension ".dll"
   targetdir "bin"
   files { "gta-antispam.c" }
   entrypoint "DllMain"
