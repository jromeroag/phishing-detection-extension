[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z][a-z0-9-]{4,28}[a-z0-9]$')]
    [string]$ProjectId,

    [string]$Region = "southamerica-west1",
    [string]$ServiceName = "escudo-transparente-api",

    [ValidatePattern('^$|^[a-p]{32}$')]
    [string]$ExtensionId = "",

    [switch]$ConfigureVirusTotal,
    [switch]$ConfigureGoogleSafeBrowsing,
    [switch]$ConfigurePhishTank,
    [switch]$ConfigureIPQualityScore,
    [switch]$ConfigureAllApis
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendPath = Join-Path $ProjectRoot "backend"
$ConfiguratorPath = Join-Path $ProjectRoot "tools\configure_extension.py"
$RuntimeServiceAccount = "escudo-cloud-run@$ProjectId.iam.gserviceaccount.com"

function Invoke-Gcloud {
    param([string[]]$Arguments)
    & gcloud @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Falló el comando: gcloud $($Arguments -join ' ')"
    }
}

function Set-CloudSecret {
    param(
        [string]$SecretName,
        [string]$Prompt
    )
    $SecureKey = Read-Host $Prompt -AsSecureString
    $Pointer = [IntPtr]::Zero
    $SecretTempPath = $null
    $PlainKey = $null
    try {
        $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
        $PlainKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
        if ([string]::IsNullOrWhiteSpace($PlainKey)) {
            throw "$SecretName no puede estar vacía."
        }
        $SecretTempPath = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($SecretTempPath, $PlainKey, [Text.UTF8Encoding]::new($false))
        & gcloud secrets describe $SecretName --project=$ProjectId *> $null
        if ($LASTEXITCODE -eq 0) {
            & gcloud secrets versions add $SecretName --data-file=$SecretTempPath --project=$ProjectId
        } else {
            & gcloud secrets create $SecretName --data-file=$SecretTempPath --replication-policy=automatic --project=$ProjectId
        }
        if ($LASTEXITCODE -ne 0) {
            throw "No se pudo guardar $SecretName en Secret Manager."
        }
    } finally {
        if ($Pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
        }
        if ($SecretTempPath -and (Test-Path -LiteralPath $SecretTempPath)) {
            Remove-Item -LiteralPath $SecretTempPath -Force
        }
        $PlainKey = $null
    }
}

if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    throw "No se encontró Google Cloud CLI. Instálalo y ejecuta: gcloud init"
}

$ActiveAccount = & gcloud auth list --filter="status:ACTIVE" --format="value(account)" | Select-Object -First 1
if (-not $ActiveAccount) {
    throw "No hay una sesión activa. Ejecuta: gcloud auth login"
}

Write-Host "Configurando el proyecto $ProjectId..."
Invoke-Gcloud @("config", "set", "project", $ProjectId)
Invoke-Gcloud @(
    "services", "enable",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "safebrowsing.googleapis.com",
    "--project=$ProjectId"
)

& gcloud iam service-accounts describe $RuntimeServiceAccount --project=$ProjectId *> $null
if ($LASTEXITCODE -ne 0) {
    Invoke-Gcloud @(
        "iam", "service-accounts", "create", "escudo-cloud-run",
        "--display-name=Escudo Transparente Cloud Run",
        "--project=$ProjectId"
    )
}

$SecretDefinitions = @(
    [PSCustomObject]@{
        Name = "VT_API_KEY"
        Configure = [bool]($ConfigureAllApis -or $ConfigureVirusTotal)
        Prompt = "Ingresa VT_API_KEY (no se mostrará)"
    },
    [PSCustomObject]@{
        Name = "GOOGLE_SAFE_BROWSING_API_KEY"
        Configure = [bool]($ConfigureAllApis -or $ConfigureGoogleSafeBrowsing)
        Prompt = "Ingresa GOOGLE_SAFE_BROWSING_API_KEY (no se mostrará)"
    },
    [PSCustomObject]@{
        Name = "PHISHTANK_API_KEY"
        Configure = [bool]($ConfigureAllApis -or $ConfigurePhishTank)
        Prompt = "Ingresa PHISHTANK_API_KEY (no se mostrará)"
    },
    [PSCustomObject]@{
        Name = "IPQS_API_KEY"
        Configure = [bool]($ConfigureAllApis -or $ConfigureIPQualityScore)
        Prompt = "Ingresa IPQS_API_KEY (no se mostrará)"
    }
)

foreach ($Definition in $SecretDefinitions) {
    if ($Definition.Configure) {
        Set-CloudSecret -SecretName $Definition.Name -Prompt $Definition.Prompt
    }
}

$SecretBindings = @()
foreach ($Definition in $SecretDefinitions) {
    & gcloud secrets describe $Definition.Name --project=$ProjectId *> $null
    if ($LASTEXITCODE -eq 0) {
        Invoke-Gcloud @(
            "secrets", "add-iam-policy-binding", $Definition.Name,
            "--member=serviceAccount:$RuntimeServiceAccount",
            "--role=roles/secretmanager.secretAccessor",
            "--project=$ProjectId"
        )
        $SecretBindings += "$($Definition.Name)=$($Definition.Name):latest"
    }
}

$AllowedOrigin = if ($ExtensionId) {
    "chrome-extension://$ExtensionId"
} else {
    "chrome-extension://*"
}

$DeployArguments = @(
    "run", "deploy", $ServiceName,
    "--source=$BackendPath",
    "--region=$Region",
    "--project=$ProjectId",
    "--platform=managed",
    "--allow-unauthenticated",
    "--service-account=$RuntimeServiceAccount",
    "--memory=512Mi",
    "--cpu=1",
    "--concurrency=20",
    "--timeout=15s",
    "--min-instances=0",
    "--max-instances=1",
    "--set-env-vars=ALLOWED_EXTENSION_ORIGINS=$AllowedOrigin",
    "--quiet"
)
if ($SecretBindings.Count -gt 0) {
    $DeployArguments += "--update-secrets=$($SecretBindings -join ',')"
}

Write-Host "Construyendo y publicando el backend en Cloud Run..."
Invoke-Gcloud $DeployArguments

$ServiceUrl = & gcloud run services describe $ServiceName `
    --region=$Region `
    --project=$ProjectId `
    --format="value(status.url)"
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($ServiceUrl)) {
    throw "El servicio se publicó, pero no fue posible obtener su URL."
}
$ServiceUrl = $ServiceUrl.Trim()

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $ConfiguratorPath $ServiceUrl
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $ConfiguratorPath $ServiceUrl
} else {
    throw "Cloud Run quedó publicado, pero falta Python para configurar la extensión."
}
if ($LASTEXITCODE -ne 0) {
    throw "Cloud Run quedó publicado, pero no se pudo actualizar extension/config.js."
}

$Health = Invoke-RestMethod -Uri "$ServiceUrl/health" -TimeoutSec 30
if ($Health.status -ne "ok") {
    throw "El servicio respondió, pero la comprobación de salud no fue correcta."
}

Write-Host ""
Write-Host "Despliegue terminado correctamente." -ForegroundColor Green
Write-Host "API: $ServiceUrl"
Write-Host "Fuentes configuradas: VirusTotal=$($Health.virustotal_configured), Google=$($Health.google_safe_browsing_configured), PhishTank=$($Health.phishtank_configured), IPQS=$($Health.ipqualityscore_configured)"
Write-Host "Ahora abre chrome://extensions, pulsa Actualizar y prueba la extensión."
