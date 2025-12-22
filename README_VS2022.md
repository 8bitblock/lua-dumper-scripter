# Visual Studio 2022 Setup Instructions

This project is a raw C++ codebase designed for Visual Studio 2022 on Windows.

## Directory Structure

*   `src/gui`: The main Injector/GUI application (EXE).
*   `src/agent`: The payload library (DLL) to be injected.
*   `src/injector`: Static library containing injection logic.
*   `src/target`: A dummy target application for testing.
*   `external/imgui`: Dear ImGui source code.

## Prerequisites

1.  **Visual Studio 2022** with "Desktop development with C++".
2.  **SDL2**: Download development libraries for MSVC (NuGet package `SDL2` and `SDL2.redist` recommended, or download from libsdl.org).
3.  **Lua 5.4**: Download binaries (DLL and Headers) for Windows (e.g., from lua-users.org or nuget `lua`).

## Setup Steps

### 1. Create Solution
1.  Open Visual Studio 2022.
2.  Create a "Blank Solution" named `LuaTool`.

### 2. Project: GUI (The Application)
1.  Add a New Project -> "Console App" (C++) -> named `LuaTool`.
2.  **Add Source Files**:
    *   Right-click Project -> Add -> Existing Item.
    *   Navigate to `src/gui/` and select `main.cpp`, `RemoteAgent.h`, `RemoteAgent.cpp`, `ProcessManager.h`, and `ProcessManager.cpp`.
    *   Navigate to `src/common/` and select `lua_ipc.h`.
    *   Navigate to `src/injector/` and select `injector.cpp` and `injector.h`.
3.  **Add ImGui Source Files (CRITICAL)**:
    *   **WARNING**: Do NOT add these files twice. If you see errors like `already defined in ...`, remove all ImGui files from the project and re-add them exactly once.
    *   Navigate to `external/imgui/` and add these **5 files**:
        1.  `imgui.cpp` (Core - Fixes 'Unresolved external symbol ImGuiPlatformIO::...')
        2.  `imgui_draw.cpp`
        3.  `imgui_tables.cpp`
        4.  `imgui_widgets.cpp`
        5.  `imgui_demo.cpp` (Optional, but good for reference)
    *   Navigate to `external/imgui/backends/` and add these **2 files**:
        1.  `imgui_impl_sdl2.cpp`
        2.  `imgui_impl_opengl3.cpp`
    *   *If you miss `imgui.cpp`, you will get unresolved externals for `ClearRendererHandlers`.*
    *   *If you add files twice, you will get `already defined` errors.*
4.  **Properties**:
    *   Right-click Project -> Properties.
    *   **C/C++ -> General -> Additional Include Directories**:
        *   `$(SolutionDir)external/imgui`
        *   `$(SolutionDir)external/imgui/backends`
        *   `$(SolutionDir)src/common`
        *   *Path to SDL2 Include* (e.g., `C:\SDL2\include` or managed by NuGet)
    *   **Linker -> General -> Additional Library Directories**: *Path to SDL2 Lib* (e.g., `C:\SDL2\lib\x64`).
    *   **Linker -> Input -> Additional Dependencies**: `SDL2.lib`;`SDL2main.lib`;`opengl32.lib`.

### 3. Project: Agent (The DLL)
1.  Add a New Project -> "Dynamic-Link Library (DLL)" (C++) -> named `Agent`.
2.  Add existing items from `src/agent/main.cpp` and `src/common/lua_ipc.h`.
3.  **Properties**:
    *   **C/C++ -> General -> Additional Include Directories**: `$(SolutionDir)src/common`.
    *   **Linker -> System -> SubSystem**: Windows.

### 4. Project: DummyTarget (Testing)
1.  Add a New Project -> "Console App" (C++) -> named `DummyTarget`.
2.  Add existing items from `src/target/main.cpp`.
3.  Ensure `lua54.dll` is in the output directory.

## Troubleshooting

*   **Unresolved external symbol ImGui_ImplSDL2_...**: You forgot to add `external/imgui/backends/imgui_impl_sdl2.cpp` to the LuaTool project.
*   **Unresolved external symbol ImGuiPlatformIO::ClearRendererHandlers**: You forgot to add `imgui.cpp` to the LuaTool project.
*   **... already defined in imgui_widgets.obj**: You added `imgui_widgets.cpp` (or other ImGui files) to the project **twice**. Check both "Source Files" and "Header Files" filters, or delete the project and start over.
*   **Unresolved external symbol SDL_main**: Ensure `SDL2main.lib` is linked and your main function signature is correct (`int main(int argc, char** argv)`).
*   **Could not load lua54.dll**: Copy `lua54.dll` to the folder where `DummyTarget.exe` and `LuaTool.exe` are built (e.g., `x64/Debug`).

## Running
1.  Build Solution.
2.  Copy `lua54.dll` to the output folder.
3.  Run `DummyTarget`.
4.  Run `LuaTool`.
5.  Select `DummyTarget` process and click "Inject".
