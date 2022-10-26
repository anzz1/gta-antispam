workspace "gta-antispam"
   configurations { "Release" }
   platforms { "Win64" }
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

   filter "configurations:Release"
      defines "NDEBUG"
      optimize "Speed"
      symbols "Off"

   filter "platforms:Win64"
      architecture "x64"

project "gta-antispam"
   kind "SharedLib"
   language "C"
   targetname "antispam"
   targetextension ".dll"
   targetdir "bin"
   files { "gta-antispam.c" }
   entrypoint "DllMain"
