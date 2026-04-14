const WINDOWS_ONLY_HINTS: RegExp[] = [
  /\bwindows\b/i,
  /\bwin32\b/i,
  /\bwin64\b/i,
  /\bpowershell\b/i,
  /\bcmd\.exe\b/i,
  /\brundll32\b/i,
  /\bregsvr32\b/i,
  /\bwmic\b/i,
  /\bvssadmin\b/i,
  /\bbcdedit\b/i,
  /\bschtasks\b/i,
  /\bmimikatz\b/i,
  /\bmshta\b/i,
  /\bmsiexec\b/i,
  /\bhklm\\/i,
  /\bhkcu\\/i,
  /c:\\/i,
  /\\windows\\/i,
  /\\system32\\/i,
  /\\syswow64\\/i,
  /\bpe32\b/i,
  /\bportable executable\b/i,
  // YARA module imports that target non-Linux binary formats
  /import\s+"pe"/i,
  /import\s+"dotnet"/i,
  /import\s+"macho"/i,
  // YARA PE module attribute access (pe.is_pe, pe.version_info, pe.DLL, etc.)
  /\bpe\.[a-z]/i,
];

const LINUX_HINTS: RegExp[] = [
  /\blinux\b/i,
  /\bunix\b/i,
  /\bposix\b/i,
  /\belf\b/i,
  /\/proc\//i,
  /\/sys\//i,
  /\/etc\//i,
  /\/dev\//i,
  /\bsystemd\b/i,
  /\bselinux\b/i,
  /\bapparmor\b/i,
  /\bbtrfs\b/i,
  /\bzfs\b/i
];

function anyMatch(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

// Keep unknown or generic rules; only drop entries that are clearly Windows-only.
export function isLinuxRelevantContent(...parts: Array<unknown>): boolean {
  const text = parts
    .flatMap((part) => {
      if (Array.isArray(part)) {
        return part.map((entry) => String(entry ?? ''));
      }
      return [String(part ?? '')];
    })
    .join('\n')
    .toLowerCase();

  if (!text.trim()) {
    return true;
  }

  const hasWindowsOnlyHints = anyMatch(text, WINDOWS_ONLY_HINTS);
  if (!hasWindowsOnlyHints) {
    return true;
  }

  const hasLinuxHints = anyMatch(text, LINUX_HINTS);
  return hasLinuxHints;
}
