# SPDX-License-Identifier: AGPL-3.0-only
# =============================================================================
# 仅核验并删除调用方登记的自有临时对象；目录与文件使用同一套边界。
# =============================================================================
param(
    [Parameter(Mandatory = $true)][string]$Workspace,
    [Parameter(Mandatory = $true)][string]$Cache,
    [Parameter(Mandatory = $true)][string]$Candidate,
    [string]$Prefix,
    [ValidateSet('remove', 'move')][string]$Action = 'remove',
    [string]$Destination
)

$ErrorActionPreference = 'Stop'

function Get-TaskAbsolutePath([string]$TaskPath) {
    if (-not [IO.Path]::IsPathRooted($TaskPath)) { throw 'Absolute path required.' }
    return [IO.Path]::GetFullPath($TaskPath).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Assert-TaskRegularItem($TaskItem) {
    if (($TaskItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point rejected.' }
    if ($TaskItem -isnot [IO.FileInfo] -and $TaskItem -isnot [IO.DirectoryInfo]) { throw 'Regular file or directory required.' }
}

function Assert-TaskPathChain([string]$TaskPath) {
    $taskCurrent = $TaskPath
    while ($taskCurrent) {
        try { $taskItem = Get-Item -LiteralPath $taskCurrent -Force; Assert-TaskRegularItem $taskItem }
        catch [System.Management.Automation.ItemNotFoundException] { }
        $taskParent = [IO.Path]::GetDirectoryName($taskCurrent)
        if (-not $taskParent -or $taskParent -eq $taskCurrent) { break }
        $taskCurrent = $taskParent
    }
}

function Get-TaskTreeMetadata($TaskItem) {
    $taskCount = 0
    $taskSize = [long]0
    $taskStack = [Collections.Generic.Stack[IO.FileSystemInfo]]::new()
    $taskStack.Push($TaskItem)
    while ($taskStack.Count -gt 0) {
        $taskEntry = $taskStack.Pop()
        Assert-TaskRegularItem $taskEntry
        $taskCount++
        if ($taskEntry -is [IO.DirectoryInfo]) {
            foreach ($taskChild in Get-ChildItem -LiteralPath $taskEntry.FullName -Force) {
                Assert-TaskRegularItem $taskChild
                $taskStack.Push($taskChild)
            }
        } else {
            $taskSize += $taskEntry.Length
            $null = Get-FileHash -LiteralPath $taskEntry.FullName -Algorithm SHA256
        }
    }
    return @{Entries = $taskCount; Bytes = $taskSize}
}

try {
    $taskWorkspacePath = Get-TaskAbsolutePath $Workspace
    $taskCachePath = Get-TaskAbsolutePath $Cache
    $taskCandidatePath = Get-TaskAbsolutePath $Candidate
    $taskExpectedCache = [IO.Path]::GetFullPath([IO.Path]::Combine($taskWorkspacePath, '.cache', 'tmp'))
    if (-not $taskCachePath.Equals($taskExpectedCache, [StringComparison]::OrdinalIgnoreCase)) { throw 'Owned cache boundary rejected.' }
    Assert-TaskPathChain $taskCandidatePath
    if ($Action -eq 'move') {
        if (-not $Destination -or [IO.Path]::IsPathRooted($Destination) -or $Destination.Contains(':') -or $Destination.Contains('\') -or
            $Destination.Split('/') -contains '..' -or $Destination.Split('/') -contains '.' -or $Destination -eq '.git' -or $Destination.StartsWith('.git/', [StringComparison]::OrdinalIgnoreCase)) { throw 'Repository-relative destination required.' }
        $taskDestinationPath = Get-TaskAbsolutePath ([IO.Path]::Combine($taskWorkspacePath, $Destination))
        if (-not $taskDestinationPath.StartsWith($taskWorkspacePath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
            -not $taskCandidatePath.StartsWith($taskCachePath + [IO.Path]::DirectorySeparatorChar + 'remote-pull.', [StringComparison]::OrdinalIgnoreCase)) { throw 'Download move boundary rejected.' }
        Assert-TaskPathChain $taskDestinationPath
        if (Test-Path -LiteralPath $taskDestinationPath) { throw 'Existing destination retained.' }
        $taskCandidateItem = Get-Item -LiteralPath $taskCandidatePath -Force
        $taskMetadata = Get-TaskTreeMetadata $taskCandidateItem
        $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($taskDestinationPath))
        Assert-TaskPathChain $taskDestinationPath
        if ($taskCandidateItem -is [IO.DirectoryInfo]) { [IO.Directory]::Move($taskCandidatePath, $taskDestinationPath) }
        else { [IO.File]::Move($taskCandidatePath, $taskDestinationPath) }
        [Console]::Error.WriteLine(('[move] Checked repository destination and download: {0} entries, {1} bytes, no reparse points.' -f $taskMetadata.Entries, $taskMetadata.Bytes))
        exit 0
    }
    if ($Prefix -notmatch '^[A-Za-z0-9_-]+\.$' -or
        -not [IO.Path]::GetDirectoryName($taskCandidatePath).Equals($taskCachePath, [StringComparison]::OrdinalIgnoreCase) -or
        -not [IO.Path]::GetFileName($taskCandidatePath).StartsWith($Prefix, [StringComparison]::Ordinal) -or
        [IO.Path]::GetFileName($taskCandidatePath).Length -le $Prefix.Length) { throw 'Owned temp boundary rejected.' }
    try { $taskCandidateItem = Get-Item -LiteralPath $taskCandidatePath -Force }
    catch [System.Management.Automation.ItemNotFoundException] { exit 0 }
    $taskMetadata = Get-TaskTreeMetadata $taskCandidateItem
    [Console]::Error.WriteLine(('[cleanup] Checked owned temp {0}: {1} entries, {2} bytes, no reparse points.' -f $taskCandidatePath, $taskMetadata.Entries, $taskMetadata.Bytes))
    Remove-Item -LiteralPath $taskCandidatePath -Recurse -Force
    exit 0
} catch {
    [Console]::Error.WriteLine('[cleanup] Check or native cleanup failed; target retained: ' + $_.Exception.Message)
    exit 1
}
