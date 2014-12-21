#include <windows.h>
#include <stdio.h>

void DisplayError(DWORD code) {
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    char buffer[10000];
    LPVOID lpMsgBuf;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL);

    snprintf(buffer, sizeof(buffer)-1, "error %d: %s", code, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)buffer, TEXT("Error"), MB_OK); 
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   PSTR lpCmdLine, INT nCmdShow)  {


    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    DWORD perl_pid;
    HANDLE pipe;
    char buffer[128];
    DWORD bytes_read;
    DWORD last_error;

    perl_pid = strtol(lpCmdLine, &lpCmdLine, 10);
    if (*(lpCmdLine++) != ':')
        return 1;
    pipe = (HANDLE)strtol(lpCmdLine, NULL, 10);

    HANDLE perl = OpenProcess(PROCESS_DUP_HANDLE,
                              0, perl_pid);
    if (!perl) {
        last_error = GetLastError();
        DisplayError(last_error);
    }

    if (!DuplicateHandle(perl, pipe, GetCurrentProcess(),
                         &pipe, 0, 0, DUPLICATE_SAME_ACCESS)) {
        DisplayError(GetLastError());
        return 2;
    }

    while (ReadFile(pipe, buffer, sizeof(buffer) - 1, &bytes_read, NULL)) {
        DWORD bytes_written;
        char *p = buffer;
    
        buffer[bytes_read] = '\0';


        while (bytes_read) {
            if (WriteFile(out, p, bytes_read, &bytes_written, NULL)) {
                bytes_read -= bytes_written;
                p += bytes_written;
            }
            else
                break;
        }
    }
    last_error = GetLastError();
    /*DisplayError(last_error); */

    return (last_error == ERROR_BROKEN_PIPE ? 0 : last_error);
}
