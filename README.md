# notepad_dll_injection

This repository is meant for reminding me of the stuff I've learnt along the path. Work is done during last 2 days.

## Descriptions

Code in the repository does the job to hijack the `ReadFile` and `WriteFile` API of **win32 version notepad**. To test out the result, follow the steps:

1. Change the path string in the source code of project NotepadInjector into proper value. 

2. Open the ` NotepadInjector.vcxproj` with Visual Studio 2019 (Not guaranteed to work with other version) and generate the solution.

3. Go into the Debug directory of project NotepadInjector and run the executable with administrator permissions while keeping the attached `Notepad.exe` running.


In theory, code included will also work with other 32bit version PE.

## Question and Answer

Q: How to get every open notepad.exe injected and the new ones as well?

A: Try to solve it with a infinite loop. 
