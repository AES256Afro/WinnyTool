; ============================================================================
; WinnyTool NSIS Installer Script
; Nullsoft Scriptable Install System (NSIS) v3.x
;
; Build with:   makensis winnytool_setup.nsi
; Prerequisites: Place the PyInstaller output in ..\dist\ before compiling.
; ============================================================================

; ---------------------------------------------------------------------------
; Includes
; ---------------------------------------------------------------------------
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

; ---------------------------------------------------------------------------
; General configuration
; ---------------------------------------------------------------------------
!define PRODUCT_NAME        "WinnyTool"
!define PRODUCT_VERSION     "1.4.0"
!define PRODUCT_PUBLISHER   "AES256Afro"
!define PRODUCT_WEB_SITE    "https://github.com/AES256Afro/WinnyTool"
!define PRODUCT_DIR_REGKEY  "Software\${PRODUCT_NAME}"
!define PRODUCT_UNINST_KEY  "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "..\dist\WinnyTool_Setup_v${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUnInstDetails show

; ---------------------------------------------------------------------------
; Installer icon
; ---------------------------------------------------------------------------
!define MUI_ICON   "..\assets\winnytool.ico"
!define MUI_UNICON "..\assets\winnytool.ico"

; ---------------------------------------------------------------------------
; MUI2 Branding
; ---------------------------------------------------------------------------
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to ${PRODUCT_NAME} Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PRODUCT_NAME} v${PRODUCT_VERSION}.$\r$\n$\r$\nWindows System Diagnostic & Optimization Tool.$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN "$INSTDIR\WinnyTool.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${PRODUCT_NAME}"

; ---------------------------------------------------------------------------
; Installer pages
; ---------------------------------------------------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; ---------------------------------------------------------------------------
; Uninstaller pages
; ---------------------------------------------------------------------------
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; ---------------------------------------------------------------------------
; Language
; ---------------------------------------------------------------------------
!insertmacro MUI_LANGUAGE "English"

; ---------------------------------------------------------------------------
; Version information embedded in the installer EXE
; ---------------------------------------------------------------------------
VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName"     "${PRODUCT_NAME}"
VIAddVersionKey "ProductVersion"  "${PRODUCT_VERSION}"
VIAddVersionKey "CompanyName"     "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT_NAME} Installer"
VIAddVersionKey "LegalCopyright"  "Copyright (c) ${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileVersion"     "${PRODUCT_VERSION}.0"

; ===========================================================================
; SECTION: Core files (required)
; ===========================================================================
Section "!${PRODUCT_NAME} (required)" SEC_CORE
    SectionIn RO ; read-only, cannot be deselected

    SetOutPath "$INSTDIR"

    ; Main executable
    File "..\dist\WinnyTool.exe"

    ; Data files
    SetOutPath "$INSTDIR\data"
    File /r "..\data\*.*"

    ; Asset files
    SetOutPath "$INSTDIR\assets"
    File /r "..\assets\*.*"

    ; Documentation
    SetOutPath "$INSTDIR"
    File "..\LICENSE"
    File "..\README.md"

    ; ----- Start Menu shortcuts -----
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortcut  "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" \
                    "$INSTDIR\WinnyTool.exe" "" "$INSTDIR\assets\winnytool.ico"
    CreateShortcut  "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall ${PRODUCT_NAME}.lnk" \
                    "$INSTDIR\Uninstall.exe"

    ; ----- Write uninstaller -----
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; ----- Add/Remove Programs registry -----
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName"     "${PRODUCT_NAME}"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion"  "${PRODUCT_VERSION}"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher"        "${PRODUCT_PUBLISHER}"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout"     "${PRODUCT_WEB_SITE}"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon"      "$INSTDIR\assets\winnytool.ico"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString"  "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation"  "$INSTDIR"
    WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "NoRepair" 1

    ; Calculate installed size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "EstimatedSize" $0

    ; Store install path for future reference
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "InstallDir" "$INSTDIR"
SectionEnd

; ===========================================================================
; SECTION: Desktop shortcut (optional)
; ===========================================================================
Section "Desktop Shortcut" SEC_DESKTOP
    CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" \
                   "$INSTDIR\WinnyTool.exe" "" "$INSTDIR\assets\winnytool.ico"
SectionEnd

; ---------------------------------------------------------------------------
; Section descriptions
; ---------------------------------------------------------------------------
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_CORE}    "Install ${PRODUCT_NAME} core files, Start Menu shortcuts, and register in Add/Remove Programs."
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP}  "Create a shortcut on your Desktop for quick access."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ===========================================================================
; UNINSTALLER
; ===========================================================================
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\WinnyTool.exe"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\Uninstall.exe"

    ; Remove data directory
    RMDir /r "$INSTDIR\data"

    ; Remove assets directory
    RMDir /r "$INSTDIR\assets"

    ; Remove install directory (only if empty after above)
    RMDir "$INSTDIR"

    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall ${PRODUCT_NAME}.lnk"
    RMDir  "$SMPROGRAMS\${PRODUCT_NAME}"

    ; Remove Desktop shortcut
    Delete "$DESKTOP\${PRODUCT_NAME}.lnk"

    ; Remove registry keys
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd
