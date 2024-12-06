.data
    syscall_id dword 0h
.code
    syscallWarpper proc
        mov syscall_id,0
        mov syscall_id,ecx
        ret
    syscallWarpper endp

    syscall proc
        mov r10,rcx
        mov eax,syscall_id
        syscall
        ret
    syscall endp
end
