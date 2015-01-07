.386

.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\user32.inc
include \masm32\include\comctl32.inc

includelib \masm32\lib\comctl32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\comdlg32.lib

IDD_SECTIONTABLE 	equ     104
IDC_SECTIONLIST       	equ     1001

SEH struct
	PrevLink 		dd ?		; the address of the previous seh structure
	CurrentHandler 	dd ?		; the address of the new exception handler
	SafeOffset 		dd ?		; The offset where it's safe to continue execution
	PrevEsp 		dd ?		; the old value in esp
	PrevEbp 		dd ?		; The old value in ebp
SEH ends


.data
AppName 			db "Virus Project Daniel", 0
ofn   OPENFILENAME <>
FilterString 			db "Executable Files (*.exe, *.dll)", 0, "*.exe;*.dll", 0
             			db "All Files", 0, "*.*", 0, 0
FileOpenError 		db "Cannot open the file for reading", 0
FileOpenMappingError 	db "Cannot open the file for memory mapping", 0
FileMappingError 		db "Cannot map the file into memory", 0
FileInValidPE 			db "This file is not a valid PE", 0
template 			db "%08lx", 0
SectionName			db "Section", 0
VirtualSize			db "V.Size", 0
VirtualAddress		db "V.Address", 0
SizeOfRawData		db "Raw Size", 0
RawOffset			db "Raw Offset", 0
Characteristics		db "Characteristics", 0
SuspiciousFile		db "Suspicious file detected", 0
VirusFoundMessage		db "This file is infected with Win32.Adson", 0
VirusFoundCaption		db "Malware Detected", 0
VirusName			db ".Adson", 0
AdsonName			db "The name of the last section is identical to that of the Adson Virus.", 0
AdsonVirtualSize		db "Virtual size of the last section resembles that of the Adson Virus.", 0
AdsonCharacteristic		db "The characteristic of the last section is identical to the Adson Virus.", 0

.data?
hInstance 		dd ?
buffer 			db 512 dup(?)
hFile 			dd ?
hMapping 		dd ?
pMapping 		dd ?
ValidPE 		dd ?
NumberOfSections 	dw ?
AdsonTrigger1	dd ?
AdsonTrigger2	dd ?
AdsonTrigger3	dd ?


.code
start proc
LOCAL seh:SEH
	invoke GetModuleHandle, NULL
	mov hInstance, eax
	mov ofn.lStructSize, SIZEOF ofn
	mov  ofn.lpstrFilter, OFFSET FilterString
	mov  ofn.lpstrFile, OFFSET buffer
	mov  ofn.nMaxFile, 512
	mov  ofn.Flags, OFN_FILEMUSTEXIST or \
                       OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
                       OFN_EXPLORER or OFN_HIDEREADONLY
	invoke GetOpenFileName, ADDR ofn
	.if eax == TRUE
		invoke CreateFile, addr buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
		.if eax!=INVALID_HANDLE_VALUE
			mov hFile, eax
			invoke CreateFileMapping, hFile, NULL, PAGE_READONLY, 0, 0, 0
			.if eax!=NULL
				mov hMapping, eax
				invoke MapViewOfFile, hMapping, FILE_MAP_READ, 0, 0, 0
				.if eax!=NULL
					mov pMapping, eax
					assume fs:nothing
					push fs:[0]
					pop seh.PrevLink
					mov seh.CurrentHandler, offset SEHHandler
					mov seh.SafeOffset, offset FinalExit
					lea eax, seh
					mov fs:[0], eax
					mov seh.PrevEsp, esp
					mov seh.PrevEbp, ebp
					mov edi, pMapping
					assume edi:ptr IMAGE_DOS_HEADER
					.if [edi].e_magic == IMAGE_DOS_SIGNATURE
						add edi, [edi].e_lfanew
						assume edi:ptr IMAGE_NT_HEADERS
						.if [edi].Signature == IMAGE_NT_SIGNATURE
							mov ValidPE, TRUE
						.else
							mov ValidPE, FALSE
						.endif
					.else
						mov ValidPE, FALSE
					.endif
FinalExit:
					push seh.PrevLink
					pop fs:[0]
					.if ValidPE == TRUE
						call ShowSectionInfo
					.else
						invoke MessageBox, 0, addr FileInValidPE, addr AppName, MB_OK+MB_ICONINFORMATION
					.endif
					invoke UnmapViewOfFile, pMapping
				.else
					invoke MessageBox, 0, addr FileMappingError, addr AppName, MB_OK+MB_ICONERROR
				.endif
				invoke CloseHandle, hMapping
			.else
				invoke MessageBox, 0, addr FileOpenMappingError, addr AppName, MB_OK+MB_ICONERROR
			.endif
			invoke CloseHandle, hFile
		.else
			invoke MessageBox, 0, addr FileOpenError, addr AppName, MB_OK+MB_ICONERROR
		.endif
	.endif
	invoke ExitProcess, 0
	invoke InitCommonControls
start endp

SEHHandler proc C uses edx pExcept:DWORD, pFrame:DWORD, pContext:DWORD, pDispatch:DWORD
	mov edx, pFrame
	assume edx:ptr SEH
	mov eax, pContext
	assume eax:ptr CONTEXT
	push [edx].SafeOffset
	pop [eax].regEip
	push [edx].PrevEsp
	pop [eax].regEsp
	push [edx].PrevEbp
	pop [eax].regEbp
	mov ValidPE, FALSE
	mov eax, ExceptionContinueExecution
	ret
SEHHandler endp


DlgProc proc uses edi esi hDlg:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD
	LOCAL lvc:LV_COLUMN 				; LV = List View
	LOCAL lvi:LV_ITEM
	.if uMsg == WM_INITDIALOG
		mov esi, lParam
		mov lvc.imask, LVCF_FMT or LVCF_TEXT or LVCF_WIDTH or LVCF_SUBITEM
		mov lvc.fmt, LVCFMT_LEFT
		mov lvc.lx, 81
		mov lvc.iSubItem, 0
		mov lvc.pszText, offset SectionName
		invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 0, addr lvc
		inc lvc.iSubItem
		mov lvc.fmt, LVCFMT_RIGHT
		mov lvc.pszText, offset VirtualSize
		invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 1, addr lvc
		inc lvc.iSubItem
		mov lvc.pszText, offset VirtualAddress
		invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 2, addr lvc
		inc lvc.iSubItem
		mov lvc.pszText, offset SizeOfRawData
		invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 3, addr lvc
		inc lvc.iSubItem
		mov lvc.pszText, offset RawOffset
		invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 4, addr lvc
		inc lvc.iSubItem
		mov lvc.pszText, offset Characteristics
		invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTCOLUMN, 5, addr lvc
		mov ax, NumberOfSections
		movzx eax, ax
		mov edi, eax
		mov lvi.imask, LVIF_TEXT
		mov lvi.iItem, 0
		assume esi:ptr IMAGE_SECTION_HEADER
		.while edi > 0
			mov lvi.iSubItem, 0
			invoke RtlZeroMemory, addr buffer, 9
			invoke lstrcpyn, addr buffer, addr [esi].Name1, 8
			lea eax, buffer
			mov lvi.pszText, eax
			push edi
			lea edi, [esi].Name1
			push esi
			cld
			mov ecx, 6
			lea esi, VirusName
			repz cmpsb
			jne continuation1
			invoke MessageBox, 0, addr AdsonName, addr SuspiciousFile, MB_OK+MB_ICONINFORMATION
			mov AdsonTrigger1, TRUE

		continuation1:
			pop esi
			pop edi
			invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_INSERTITEM, 0, addr lvi


			invoke wsprintf, addr buffer, addr template, [esi].Misc.VirtualSize
			lea eax, buffer
			mov lvi.pszText, eax
			cmp [esi].Misc.VirtualSize, 00001804h
			jne continuation2
			invoke MessageBox, 0, addr AdsonVirtualSize, addr SuspiciousFile, MB_OK+MB_ICONINFORMATION
			mov AdsonTrigger2, TRUE

		continuation2:
			inc lvi.iSubItem
			invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_SETITEM, 0, addr lvi


			invoke wsprintf, addr buffer, addr template, [esi].VirtualAddress
			lea eax, buffer
			mov lvi.pszText, eax
			inc lvi.iSubItem
			invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_SETITEM, 0, addr lvi


			invoke wsprintf, addr buffer, addr template, [esi].SizeOfRawData
			lea eax, buffer
			mov lvi.pszText, eax
			inc lvi.iSubItem
			invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_SETITEM, 0, addr lvi


			invoke wsprintf, addr buffer, addr template, [esi].PointerToRawData
			lea eax, buffer
			mov lvi.pszText, eax
			inc lvi.iSubItem
			invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_SETITEM, 0, addr lvi


			invoke wsprintf, addr buffer, addr template, [esi].Characteristics
			lea eax, buffer
			mov lvi.pszText, eax
			cmp [esi].Characteristics, 0e0000020h
			jne continuation3
			invoke MessageBox, 0, addr AdsonCharacteristic, addr SuspiciousFile, MB_OK+MB_ICONINFORMATION
			mov AdsonTrigger3, TRUE

		continuation3:
			inc lvi.iSubItem
			invoke SendDlgItemMessage, hDlg, IDC_SECTIONLIST, LVM_SETITEM, 0, addr lvi

			inc lvi.iItem
			dec edi
			add esi, sizeof IMAGE_SECTION_HEADER
		.endw
			mov eax, AdsonTrigger1
			and eax, AdsonTrigger2
			and eax, AdsonTrigger3
			.if eax == TRUE
				invoke MessageBox, 0, addr VirusFoundMessage, addr VirusFoundCaption, MB_OK+MB_ICONWARNING
			.endif
	.elseif uMsg == WM_CLOSE
		invoke EndDialog, hDlg, NULL
	.else
		mov eax, FALSE
		ret
	.endif
	mov eax, TRUE
	ret
DlgProc endp

ShowSectionInfo proc uses edi
	mov edi, pMapping
	assume edi:ptr IMAGE_DOS_HEADER
	add edi, [edi].e_lfanew
	assume edi:ptr IMAGE_NT_HEADERS
	mov ax, [edi].FileHeader.NumberOfSections
	mov NumberOfSections, ax
	add edi, sizeof IMAGE_NT_HEADERS
	invoke DialogBoxParam, hInstance, IDD_SECTIONTABLE, NULL, addr DlgProc, edi
	ret
ShowSectionInfo endp

end start
