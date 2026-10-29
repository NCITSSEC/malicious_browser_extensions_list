param(
    [string]$Repository = 'NCITSSEC/malicious_browser_extensions_list',
    [switch]$SkipRun,
    [switch]$UseEnvironmentToken,
    [switch]$CleanupTests,
    [switch]$DiagnoseOnly,
    [switch]$VerifyAndCleanup,
    [switch]$RemoveUnusedWorkflow
)

$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
if ($VerifyAndCleanup -and ($SkipRun -or $DiagnoseOnly -or $CleanupTests)) {
    throw '-VerifyAndCleanup은 다른 실행 모드와 함께 사용할 수 없습니다.'
}
if ($RemoveUnusedWorkflow -and ($SkipRun -or $DiagnoseOnly -or $CleanupTests -or $VerifyAndCleanup)) {
    throw '-RemoveUnusedWorkflow은 다른 실행 모드와 함께 사용할 수 없습니다.'
}
function Read-GitHubTokenDialog {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'GitHub 배포 - 토큰 입력'
    $dialog.ClientSize = New-Object System.Drawing.Size(530, 235)
    $dialog.StartPosition = 'CenterScreen'
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.TopMost = $true

    $description = New-Object System.Windows.Forms.Label
    $description.Location = New-Object System.Drawing.Point(18, 15)
    $description.Size = New-Object System.Drawing.Size(495, 55)
    $description.Text = "대상 저장소: $Repository`r`nGitHub PAT를 붙여넣으세요. 입력값은 화면에 숨겨집니다."
    $dialog.Controls.Add($description)

    $tokenBox = New-Object System.Windows.Forms.TextBox
    $tokenBox.Location = New-Object System.Drawing.Point(20, 78)
    $tokenBox.Size = New-Object System.Drawing.Size(490, 25)
    $tokenBox.UseSystemPasswordChar = $true
    $dialog.Controls.Add($tokenBox)

    $note = New-Object System.Windows.Forms.Label
    $note.Location = New-Object System.Drawing.Point(18, 113)
    $note.Size = New-Object System.Drawing.Size(495, 60)
    $resourceOwner = ($Repository -split '/')[0]
    $note.Text = "Fine-grained PAT: Resource owner = $resourceOwner`r`nRepository access에서 대상 저장소를 선택하세요.`r`nContents / Workflows / Actions: Read and write"
    $dialog.Controls.Add($note)

    $confirmButton = New-Object System.Windows.Forms.Button
    $confirmButton.Text = '배포 진행'
    $confirmButton.Location = New-Object System.Drawing.Point(305, 188)
    $confirmButton.Size = New-Object System.Drawing.Size(100, 30)
    $confirmButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dialog.Controls.Add($confirmButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = '취소'
    $cancelButton.Location = New-Object System.Drawing.Point(415, 188)
    $cancelButton.Size = New-Object System.Drawing.Size(95, 30)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dialog.Controls.Add($cancelButton)
    $dialog.AcceptButton = $confirmButton
    $dialog.CancelButton = $cancelButton
    $dialog.ActiveControl = $tokenBox

    try {
        while ($true) {
            $result = $dialog.ShowDialog()
            if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
                throw '사용자가 토큰 입력을 취소했습니다. 배포하지 않았습니다.'
            }
            $enteredToken = $tokenBox.Text.Trim()
            if (-not [string]::IsNullOrWhiteSpace($enteredToken)) {
                return $enteredToken
            }
            $null = [System.Windows.Forms.MessageBox]::Show(
                '토큰이 비어 있습니다. GitHub PAT를 입력하세요.',
                '입력 확인',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            $dialog.DialogResult = [System.Windows.Forms.DialogResult]::None
            $dialog.ActiveControl = $tokenBox
        }
    } finally {
        $tokenBox.Clear()
        $dialog.Dispose()
    }
}

if ($UseEnvironmentToken) {
    $token = $env:GITHUB_TOKEN
} else {
    $token = Read-GitHubTokenDialog
}
if ([string]::IsNullOrWhiteSpace($token)) { throw 'GitHub 인증 정보가 없습니다. 환경 변수 사용 시 GITHUB_TOKEN을 설정하세요.' }
$token = $token.Trim()
$headers = @{
    Authorization = "Bearer $token"
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent' = 'NCITSSEC-Extension-Sync-Deploy'
}

function Invoke-RepoApi {
    param([string]$Path, [string]$Method = 'GET', $Payload = $null)
    $apiUri = "https://api.github.com/repos/$($Repository.Trim('/'))"
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $apiUri += '/' + $Path.TrimStart('/')
    }
    $arguments = @{
        Uri = $apiUri
        Method = $Method
        Headers = $headers
        TimeoutSec = 60
    }
    if ($null -ne $Payload) {
        $arguments.ContentType = 'application/json; charset=utf-8'
        $arguments.Body = [Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Depth 20 -Compress))
    }
    Write-Host "[GitHub API] $Method $apiUri"
    try {
        Invoke-RestMethod @arguments
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { '연결 실패' }
        $apiMessage = ''
        if ($_.ErrorDetails.Message) {
            try { $apiMessage = ($_.ErrorDetails.Message | ConvertFrom-Json).message } catch { }
        }
        $hint = switch ($statusCode) {
            401 { '토큰 값 또는 만료 여부를 확인하세요.' }
            403 { '토큰의 저장소 권한과 조직 승인 여부를 확인하세요.' }
            404 { '요청 경로와 토큰의 대상 저장소 접근 권한을 확인하세요.' }
            422 { '브랜치 변경 충돌 또는 요청 내용을 확인하세요.' }
            default { '네트워크 연결 및 GitHub 상태를 확인하세요.' }
        }
        if ($statusCode -in @(403, 404) -and $Method -ne 'GET') {
            $resourceOwner = ($Repository -split '/')[0]
            $hint = "읽기 조회 성공만으로 쓰기 권한이 확인되지는 않습니다. Fine-grained PAT의 Resource owner=$resourceOwner, 대상 저장소 선택, Contents/Workflows/Actions Read and write 및 조직 승인 상태를 확인하세요. Classic PAT는 공개 저장소에 public_repo와 workflow 범위가 필요합니다."
        }
        throw "GitHub API 실패: $Method $apiUri (HTTP $statusCode). $apiMessage $hint"
    }
}

function Remove-RemoteTestFiles {
    param([string]$BranchPath)
    $currentRef = Invoke-RepoApi "git/ref/heads/$BranchPath"
    $currentCommit = Invoke-RepoApi "git/commits/$($currentRef.object.sha)"
    $currentTree = Invoke-RepoApi "git/trees/$($currentCommit.tree.sha)"
    $workflow = Invoke-RepoApi "contents/.github/workflows/daily_sync.yml?ref=$BranchPath"
    $workflowText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($workflow.content))
    $originalWorkflowText = $workflowText
    $workflowText = [regex]::Replace($workflowText, '(?m)^      - name: 회귀 테스트\r?\n        run: python -m unittest -q test_sync_extensions\.py\r?\n\r?\n', '')
    if ($workflowText.Contains('test_sync_extensions.py')) { throw '테스트 참조가 남아 있어 정리를 중단합니다.' }
    if ($workflowText -ceq $originalWorkflowText -and -not ($currentTree.tree | Where-Object { $_.path -eq 'test_sync_extensions.py' })) {
        Write-Output '정리할 테스트 파일이나 워크플로 테스트 단계가 없습니다.'
        return
    }
    $cleanupEntries = @(@{ path = '.github/workflows/daily_sync.yml'; mode = '100644'; type = 'blob'; content = $workflowText })
    if ($currentTree.tree | Where-Object { $_.path -eq 'test_sync_extensions.py' }) {
        $cleanupEntries += @{ path = 'test_sync_extensions.py'; mode = '100644'; type = 'blob'; sha = $null }
    }
    $cleanupTree = Invoke-RepoApi 'git/trees' 'POST' @{ base_tree = $currentCommit.tree.sha; tree = $cleanupEntries }
    $cleanupCommit = Invoke-RepoApi 'git/commits' 'POST' @{
        message = 'Remove repository test file after successful live verification'
        tree = $cleanupTree.sha
        parents = @($currentRef.object.sha)
    }
    $null = Invoke-RepoApi "git/refs/heads/$BranchPath" 'PATCH' @{ sha = $cleanupCommit.sha; force = $false }
    $verifiedTree = Invoke-RepoApi "git/trees/$($cleanupTree.sha)"
    if ($verifiedTree.tree | Where-Object { $_.path -eq 'test_sync_extensions.py' }) { throw '테스트 파일 삭제 검증에 실패했습니다.' }
    Write-Output "테스트 전용 파일 및 워크플로 단계 정리 완료: https://github.com/$Repository/commit/$($cleanupCommit.sha)"
}

function Remove-LegacyWorkflow {
    $repo = Invoke-RepoApi ''
    $branch = $repo.default_branch
    $branchPath = [Uri]::EscapeDataString($branch)
    $workflowFiles = @(Invoke-RepoApi "contents/.github/workflows?ref=$branchPath")
    $legacy = $workflowFiles | Where-Object { $_.name -eq 'blank.yml' }
    $current = $workflowFiles | Where-Object { $_.name -eq 'daily_sync.yml' }
    if (-not $current) { throw '유지할 daily_sync.yml이 없어 삭제를 중단합니다.' }
    $currentFile = Invoke-RepoApi "contents/.github/workflows/daily_sync.yml?ref=$branchPath"
    $currentText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($currentFile.content))
    if (-not $currentText.Contains('source_observations.json')) {
        throw 'daily_sync.yml의 운영 관측 이력 설정이 확인되지 않아 삭제를 중단합니다.'
    }
    if (-not $legacy) {
        Write-Output 'blank.yml은 이미 삭제되어 있습니다. daily_sync.yml을 유지합니다.'
        return
    }
    $currentWorkflow = Invoke-RepoApi 'actions/workflows/daily_sync.yml'
    if ($currentWorkflow.state -ne 'active') { throw '유지할 daily_sync.yml이 활성 상태가 아니므로 삭제를 중단합니다.' }
    $null = Invoke-RepoApi 'actions/workflows/blank.yml/disable' 'PUT'
    $null = Invoke-RepoApi 'contents/.github/workflows/blank.yml' 'DELETE' @{
        message = 'Remove duplicate legacy browser extension sync workflow'
        sha = $legacy.sha
        branch = $branch
    }
    $remaining = @(Invoke-RepoApi "contents/.github/workflows?ref=$branchPath")
    if ($remaining | Where-Object { $_.name -eq 'blank.yml' }) { throw 'blank.yml 삭제 확인에 실패했습니다.' }
    if (-not ($remaining | Where-Object { $_.name -eq 'daily_sync.yml' })) { throw 'daily_sync.yml 유지 확인에 실패했습니다.' }
    Write-Output '완료: 중복 blank.yml 비활성화 및 삭제. daily_sync.yml 유지.'
    Write-Output "https://github.com/$Repository/tree/$branch/.github/workflows"
}

try {
    if ($RemoveUnusedWorkflow) {
        Remove-LegacyWorkflow
        return
    }
    if ($DiagnoseOnly) {
        $workflowRuns = Invoke-RepoApi 'actions/workflows/daily_sync.yml/runs?per_page=1'
        $lastRun = $workflowRuns.workflow_runs | Select-Object -First 1
        if (-not $lastRun) { throw '확인할 Actions 실행이 없습니다.' }
        Write-Output "실행 결과: $($lastRun.status) / $($lastRun.conclusion)"
        Write-Output $lastRun.html_url
        $jobs = Invoke-RepoApi "actions/runs/$($lastRun.id)/jobs"
        $failedJobs = @($jobs.jobs | Where-Object { $_.conclusion -eq 'failure' })
        foreach ($job in $failedJobs) {
            $logPath = Join-Path ([IO.Path]::GetTempPath()) "ncitssec-actions-$($lastRun.id)-$($job.id).log"
            $logUri = "https://api.github.com/repos/$Repository/actions/jobs/$($job.id)/logs"
            # 파일로 직접 받아 Windows PowerShell의 text/plain 문자셋 오판을 방지한다.
            Invoke-WebRequest -Uri $logUri -Headers $headers -UseBasicParsing -TimeoutSec 60 -OutFile $logPath
            Write-Output "상세 로그 저장: $logPath"
            Get-Content -LiteralPath $logPath -Encoding UTF8 | Select-Object -Last 60 | Write-Output
        }
        return
    }
    Push-Location $taskRoot
    try {
        $hasLocalTests = Test-Path -LiteralPath (Join-Path $taskRoot 'test_sync_extensions.py') -PathType Leaf
        if ($hasLocalTests) {
            Write-Host '[1/3] 회귀 테스트 실행 (실제 IoC 수집 아님)'
            & python -m unittest -b -q test_sync_extensions.py
            if ($LASTEXITCODE -ne 0) { throw '회귀 테스트 실패: 배포를 중단합니다.' }
        } else {
            Write-Host '[1/3] 로컬 테스트 파일 없음: 회귀 테스트 생략, 실제 Actions 결과로 검증합니다.'
        }
    } finally { Pop-Location }

    Write-Host '[2/3] 저장소 확인 및 코드 반영'
    $repo = Invoke-RepoApi ''
    if ($null -ne $repo.permissions -and $repo.permissions.push -eq $false) {
        throw '이 토큰의 계정은 대상 저장소에 push 권한이 없습니다. 저장소 쓰기 권한이 있는 계정의 토큰을 사용하세요.'
    }
    $branch = $repo.default_branch
    $branchPath = [Uri]::EscapeDataString($branch)
    $reference = Invoke-RepoApi "git/ref/heads/$branchPath"
    $baseCommit = Invoke-RepoApi "git/commits/$($reference.object.sha)"
    if ($CleanupTests) {
        $workflowRuns = Invoke-RepoApi 'actions/workflows/daily_sync.yml/runs?per_page=1'
        $lastRun = $workflowRuns.workflow_runs | Select-Object -First 1
        if (-not $lastRun -or $lastRun.status -ne 'completed' -or $lastRun.conclusion -ne 'success') {
            throw '최근 Actions 실행이 성공하지 않아 테스트 파일 정리를 보류합니다. 먼저 수집 오류를 해결하고 정상 실행을 확인하세요.'
        }
    }
    # 운영 CSV 및 관측 이력은 업로드하지 않아 기존 데이터를 보존한다.
    # 테스트 파일은 로컬에서 검증하고 운영 저장소에는 다시 올리지 않는다.
    $files = @('sync_extensions.py', 'README.md', 'exclude_list.txt', '.github/workflows/daily_sync.yml', 'deploy_to_github.ps1')
    if ($CleanupTests -or -not $hasLocalTests) {
        $files = $files | Where-Object { $_ -ne 'test_sync_extensions.py' }
    }
    $entries = @()
    foreach ($file in $files) {
        $localPath = Join-Path $taskRoot $file
        if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) { throw "필수 파일 누락: $file" }
        $content = [IO.File]::ReadAllText($localPath, [Text.Encoding]::UTF8)
        if (($CleanupTests -or -not $hasLocalTests) -and $file -eq '.github/workflows/daily_sync.yml') {
            $content = [regex]::Replace($content, '(?m)^      - name: 회귀 테스트\r?\n        run: python -m unittest -q test_sync_extensions\.py\r?\n\r?\n', '')
            if ($content.Contains('test_sync_extensions.py')) { throw '워크플로의 테스트 참조를 제거하지 못해 정리를 중단합니다.' }
        }
        $entries += @{
            path = $file
            mode = '100644'
            type = 'blob'
            content = $content
        }
    }
    if ($CleanupTests) {
        $remoteTree = Invoke-RepoApi "git/trees/$($baseCommit.tree.sha)"
        if ($remoteTree.tree | Where-Object { $_.path -eq 'test_sync_extensions.py' }) {
            $entries += @{ path = 'test_sync_extensions.py'; mode = '100644'; type = 'blob'; sha = $null }
        }
    }
    $tree = Invoke-RepoApi 'git/trees' 'POST' @{ base_tree = $baseCommit.tree.sha; tree = $entries }
    $commit = Invoke-RepoApi 'git/commits' 'POST' @{
        message = 'Fix source-first-seen IoC monitoring and durable email retries'
        tree = $tree.sha
        parents = @($reference.object.sha)
    }
    # force=false: 배포 도중 다른 커밋이 올라오면 덮어쓰지 않고 실패한다.
    $null = Invoke-RepoApi "git/refs/heads/$branchPath" 'PATCH' @{ sha = $commit.sha; force = $false }
    Write-Output "반영 완료: https://github.com/$Repository/commit/$($commit.sha)"
    Write-Host '[3/3] Actions 활성화 및 실행 요청'
    $null = Invoke-RepoApi 'actions/workflows/daily_sync.yml/enable' 'PUT'
    if (-not $SkipRun) {
        $null = Invoke-RepoApi 'actions/workflows/daily_sync.yml/dispatches' 'POST' @{ ref = $branch }
        Write-Output '실행을 요청했습니다. 신규 항목이 없어도 일일 실행 결과 메일을 발송합니다.'
    }
    Write-Output "실행 결과 확인: https://github.com/$Repository/actions/workflows/daily_sync.yml"
    if ($VerifyAndCleanup) {
        Write-Host '[검증] 이번 커밋의 Actions 실행 완료를 기다립니다.'
        $deadline = [DateTime]::UtcNow.AddMinutes(65)
        $verifiedRun = $null
        do {
            $runList = Invoke-RepoApi 'actions/workflows/daily_sync.yml/runs?event=workflow_dispatch&per_page=20'
            $verifiedRun = $runList.workflow_runs | Where-Object { $_.head_sha -eq $commit.sha } | Select-Object -First 1
            if ($verifiedRun) {
                Write-Host "[검증] $($verifiedRun.status) / $($verifiedRun.conclusion)"
                if ($verifiedRun.status -eq 'completed') { break }
            }
            if ([DateTime]::UtcNow -gt $deadline) { throw 'Actions 완료 대기 시간이 초과되었습니다. 테스트 파일은 삭제하지 않았습니다.' }
            Start-Sleep -Seconds 20
        } while ($true)
        if ($verifiedRun.conclusion -ne 'success') {
            throw "실제 Actions 실행 실패: $($verifiedRun.html_url). 테스트 파일은 보존했습니다. -DiagnoseOnly로 로그를 확인하세요."
        }
        $baselineFile = Invoke-RepoApi "contents/source_observations.json?ref=$branchPath"
        $baselineState = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($baselineFile.content)) | ConvertFrom-Json
        if ($baselineState.version -ne 1 -or -not $baselineState.ids) { throw '운영 관측 이력이 확인되지 않아 정리를 중단합니다.' }
        Write-Host '[검증] 실제 수집 및 관측 이력 저장 성공. 테스트 파일을 정리합니다.'
        Remove-RemoteTestFiles $branchPath
    }
} finally {
    $headers.Clear()
    $token = $null
}
