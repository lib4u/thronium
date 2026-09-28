; Thronium installer hooks (tauri.windows.conf.json: bundle.windows.nsis.installerHooks).
;
; An installation for all users also installs ThroniumService, which runs TUN
; and the system DNS for the application. An installation for one user has no
; service and no TUN.
;
; The service is ThroniumCore.exe --thronium-service as LocalSystem, started on
; demand. Interactive users may start it (RP) but not stop or change it; the
; application starts it when it connects TUN. The firewall rule is the one the
; system and mixed TUN stacks would otherwise add for this exact path.

!define THRONIUM_SERVICE "ThroniumService"
!define THRONIUM_SERVICE_SDDL "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
!define THRONIUM_FIREWALL_RULE "sing-tun ($INSTDIR\ThroniumCore.exe)"

Var ThroniumPerMachine

; Sets $ThroniumPerMachine to 1 for an installation for all users.
!macro THRONIUM_PER_MACHINE
  StrCpy $ThroniumPerMachine 0
  !if "${INSTALLMODE}" == "both"
    ${If} $MultiUser.InstallMode == "AllUsers"
      StrCpy $ThroniumPerMachine 1
    ${EndIf}
  !else if "${INSTALLMODE}" == "perMachine"
    StrCpy $ThroniumPerMachine 1
  !endif
!macroend

; Stopping the service ends its TUN session and restores the network; its
; ThroniumCore.exe is then free to be replaced or removed.
!macro THRONIUM_STOP_SERVICE
  nsExec::ExecToLog '"$SYSDIR\net.exe" stop ${THRONIUM_SERVICE}'
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro THRONIUM_PER_MACHINE
  ${If} $ThroniumPerMachine = 1
    !insertmacro THRONIUM_STOP_SERVICE
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro THRONIUM_PER_MACHINE
  ${If} $ThroniumPerMachine = 1
    ; Create on first install; on an update the service exists and only its
    ; path may have changed.
    nsExec::ExecToLog '"$SYSDIR\sc.exe" create ${THRONIUM_SERVICE} binPath= "\"$INSTDIR\ThroniumCore.exe\" --thronium-service" start= demand obj= LocalSystem DisplayName= "Thronium"'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\sc.exe" config ${THRONIUM_SERVICE} binPath= "\"$INSTDIR\ThroniumCore.exe\" --thronium-service" start= demand obj= LocalSystem DisplayName= "Thronium"'
    Pop $0
    ${If} $0 <> 0
      DetailPrint "Thronium service was not registered ($0); TUN will be unavailable."
    ${EndIf}
    nsExec::ExecToLog '"$SYSDIR\sc.exe" description ${THRONIUM_SERVICE} "Runs TUN and the system DNS for Thronium."'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\sc.exe" sdset ${THRONIUM_SERVICE} "${THRONIUM_SERVICE_SDDL}"'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name="${THRONIUM_FIREWALL_RULE}"'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall add rule name="${THRONIUM_FIREWALL_RULE}" dir=in action=allow program="$INSTDIR\ThroniumCore.exe" protocol=TCP profile=any enable=yes'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; For the person uninstalling: autostart, link handlers and "Open with" that
  ; start this installation, and a system proxy left by an unclean exit.
  ; A running Thronium is closed first, so its own exit restores the proxy.
  ${If} $UpdateMode <> 1
    !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
    ${If} $DeleteAppDataCheckboxState = 1
      nsExec::ExecToLog '"$INSTDIR\${MAINBINARYNAME}.exe" --thronium-uninstall --with-data'
    ${Else}
      nsExec::ExecToLog '"$INSTDIR\${MAINBINARYNAME}.exe" --thronium-uninstall'
    ${EndIf}
    Pop $0
  ${EndIf}
  !insertmacro THRONIUM_PER_MACHINE
  ${If} $ThroniumPerMachine = 1
    ; Starting the service once restores what an unclean stop left (its
    ; journal); stopping it ends any session.
    nsExec::ExecToLog '"$SYSDIR\net.exe" start ${THRONIUM_SERVICE}'
    Pop $0
    !insertmacro THRONIUM_STOP_SERVICE
    ; An update runs the uninstaller of the previous version too; keep the
    ; service then, the new installer only reconfigures it.
    ${If} $UpdateMode <> 1
      nsExec::ExecToLog '"$SYSDIR\sc.exe" delete ${THRONIUM_SERVICE}'
      Pop $0
      nsExec::ExecToLog '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name="${THRONIUM_FIREWALL_RULE}"'
      Pop $0
      ; The service's journal and log live in LocalSystem's own profile.
      ${DisableX64FSRedirection}
      RMDir /r "$WINDIR\System32\config\systemprofile\AppData\Local\Thronium"
      ${EnableX64FSRedirection}
    ${EndIf}
  ${EndIf}
!macroend
