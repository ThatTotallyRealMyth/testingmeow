Branch A (param_1[0x20] == 0): the code chooses a base directory depending on the script name:

if script == “upload_files.cgi” -> base = “/usr/local/www/video”
if script == “upload_sd.cgi” -> base = “/usr/local/www/video_sd” Then it does:
sVar7 = length computed from unaff_r10 - (__src + 2)
strncpy(DAT_00064118, __src + 2, sVar7);
strcat(piVar9, DAT_00064118); Important: there is no check that DAT_00064118 does not contain “…/” or leading ‘/’ or other traversal constructs. strncpy is called with a length derived from parsing logic but there is no explicit upper-bound check against the 0x40 (64) byte DAT_00064118 buffer. After concatenation the full path (base + “/” + attacker-controlled data) is used later to open or create files.
Branch B (file upload, param_1[0x20] != 0 and bVar1 true): it parses the filename header:

pcVar2 = strstr(acStack_128, “filename="”); copy that substring into DAT_0006415c
Uses strtok(&DAT_0006415c, “\”) to split on backslash and sets DAT_00064158 to the last token Then:
if param_1[0x18c] is empty, memcpy(param_1+0x18c, “/var/run”,9) and append “/”
strcat(param_1+0x18c, DAT_00064158);
open((char *)(param_1 + 0x18c), 0x41) Problem: strtok only strips backslash () path separators (Windows-style). It does not remove forward-slash (/) nor sequences like “…/”. So an attacker-supplied filename like “…/…/…/etc/passwd” (or similar) will be appended to “/var/run/” producing “/var/run/…/…/…/etc/passwd” which resolves (when opened or accessed by the OS) to a path outside the intended directory. There is no canonicalization (realpath) or check that final path is under the intended base directory.
