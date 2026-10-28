param(
    [string]$Repository = 'NCITSSEC/malicious_browser_extensions_list',
    [switch]$SkipRun,
    [switch]$UseEnvironmentToken
)

$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
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

try {
    Push-Location $taskRoot
    try {
        Write-Host '[1/3] 회귀 테스트 실행 (실제 IoC 수집 아님)'
        & python -m unittest -b -q test_sync_extensions.py
        if ($LASTEXITCODE -ne 0) { throw '회귀 테스트 실패: 배포를 중단합니다.' }
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
    # 운영 CSV 및 관측 이력은 업로드하지 않아 기존 데이터를 보존한다.
    $files = @('sync_extensions.py', 'test_sync_extensions.py', 'README.md', 'exclude_list.txt', '.github/workflows/daily_sync.yml', 'deploy_to_github.ps1')
    $entries = @()
    foreach ($file in $files) {
        $localPath = Join-Path $taskRoot $file
        if (-not (Test-Path -LiteralPath $localPath -PathType Leaf)) { throw "필수 파일 누락: $file" }
        $entries += @{
            path = $file
            mode = '100644'
            type = 'blob'
            content = [IO.File]::ReadAllText($localPath, [Text.Encoding]::UTF8)
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
        Write-Output '첫 실행을 요청했습니다. 기준선이 없는 경우 기존 항목에 대한 메일은 보내지 않습니다.'
    }
    Write-Output "실행 결과 확인: https://github.com/$Repository/actions/workflows/daily_sync.yml"
} finally {
    $headers.Clear()
    $token = $null
}
