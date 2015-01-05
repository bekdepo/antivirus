Just a simple Win32.Adson antivirus that scans the Portable Executable(PE) for the last section. 

1) If the section's name is ".Adson" it prompts a message box with the warning.
2) If the section's Virtual Size is equal to 00001804H it prompts a message bot with the warning.
3) If the sectioon's Characteristic matches the Adson Virus, that is, it is equal to 0E0000020H, it prompts a message box with the warning.
4) Finally, if 1, 2, 3 are met, a final warning appears with the conclusion that the file is infected.

The github version exe file is compiled under Visual Studio 2012. If you are still working under Windows XP, you need to use the NMAKE utility under Visual Studio 2010. Otherwise it is not recognized as a Win32 application.
