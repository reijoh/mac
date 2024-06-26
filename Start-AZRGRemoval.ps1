<#
    .DESCRIPTION
        Delete azure resource groups according to governance rules

    .NOTES
        AUTHOR: Reidar Johansen
        LASTEDIT: June 26, 2024
#>

param(
  [Parameter(Mandatory = $false)]
  [string[]]
  $SubscriptionIgnore = @('f8354277-0bf9-4cbb-82d4-09593c068e1b'),
  [Parameter(Mandatory = $false)]
  [int]
  $DaysToKeepDefault = 7,
  [Parameter(Mandatory = $false)]
  [int]
  $DaysToKeepMax = 30,
  [Parameter(Mandatory = $false)]
  [string]
  $DaysToKeepTag = 'Keep'
)

function Remove-BackupVaults {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $Token = Get-AzAccessToken
      $RestMethodArgs = @{
        Method  = 'Post'
        Uri     = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
        Headers = @{
          Authorization  = "$($Token.Type) $($Token.Token)"
          'Content-type' = 'application/json; charset=utf-8'
        }
        Body    = @{
          query         = "resources | where type =~ 'microsoft.dataprotection/backupvaults' and resourceGroup =~ '$ResourceGroupName' | project id, name, resourceGroup"
          options       = @{
            '$top'         = 100
            '$skip'        = 0
            '$skipToken'   = ''
            'resultFormat' = 'objectArray'
          }
          subscriptions = @(
            $SubscriptionId
          )
        } | ConvertTo-Json
      }
      $Response = Invoke-RestMethod @RestMethodArgs
      if (
        $null -ne $Response -and
        [bool]($Response | Get-Member -Name 'data') -and
        $null -ne $Response.data -and
        $Response.data -is [array] -and
        $Response.data.Count -gt 0
      ) {
        foreach ($Vault in $Response.data) {
          $BackupInstances = Get-AzDataProtectionBackupInstance -VaultName $Vault.name -ResourceGroupName $Vault.resourceGroup -ErrorAction Stop
          foreach ($Instance in $BackupInstances) {
            Write-Output -InputObject "- Remove backup instance $($Instance.Name) from $($Vault.name)"
            $null = Remove-AzDataProtectionBackupInstance -InputObject $Instance -ErrorAction Stop
          }
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-ImageBuilderTemplates {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $Token = Get-AzAccessToken
      $RestMethodArgs = @{
        Method  = 'Post'
        Uri     = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
        Headers = @{
          Authorization  = "$($Token.Type) $($Token.Token)"
          'Content-type' = 'application/json; charset=utf-8'
        }
        Body    = @{
          query         = "resources | where type =~ 'microsoft.virtualmachineimages/imagetemplates' and resourceGroup =~ '$ResourceGroupName' | project id, name, resourceGroup"
          options       = @{
            '$top'         = 100
            '$skip'        = 0
            '$skipToken'   = ''
            'resultFormat' = 'objectArray'
          }
          subscriptions = @(
            $SubscriptionId
          )
        } | ConvertTo-Json
      }
      $Response = Invoke-RestMethod @RestMethodArgs
      if (
        $null -ne $Response -and
        [bool]($Response | Get-Member -Name 'data') -and
        $null -ne $Response.data -and
        $Response.data -is [array] -and
        $Response.data.Count -gt 0
      ) {
        foreach ($Template in $Response.data) {
          $Instances = Get-AzImageBuilderTemplate -SubscriptionId $SubscriptionId -ResourceGroupName $Vault.resourceGroup -ErrorAction Stop
          foreach ($Instance in $Instances) {
            Write-Output -InputObject "- Remove image builder template $($Instance.Name) from $($Vault.name)"
            $null = Remove-AzImageBuilderTemplate -InputObject $Instance -ErrorAction Stop
          }
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-OperationalInsightsWorkspace {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $Workspaces = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -ErrorAction Stop
      foreach ($Workspace in $Workspaces) {
        Write-Output -InputObject "- Delete workspace $($Workspace.Name)"
        $i = 0
        $Removed = $false
        while (-not($Removed) -and $i -lt 10) {
          try {
            $null = Remove-AzOperationalInsightsWorkspace -ResourceGroupName $Workspace.ResourceGroupName -Name $Workspace.Name -ForceDelete -Force:$true -Confirm:$false -ErrorAction Stop
            $Removed = $true
          } catch {
            $ErrorMsg = $_.ToString()
            if ($ErrorMsg -match 'Please remove the lock and try again') {
              if ($i -eq 9) {
                Write-Warning -Message $ErrorMsg
              } else {
                Start-Sleep -Seconds $SleepSeconds
              }
              $i++
            } else {
              Write-Warning -Message $ErrorMsg
              break
            }
          }
        }
      }
    } catch {
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-PrivateEndpoint {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $PrivateLinkResourceId,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $Endpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $PrivateLinkResourceId -ErrorAction SilentlyContinue
      if ($null -ne $Endpoints) {
        foreach ($Item in $Endpoints) {
          $NameSplit = $Item.Name.Split('.')
          $Name = $NameSplit[0]
          Write-Output -InputObject "- Remove private endpoint $Name for resource $PrivateLinkResourceId"
          $null = Remove-AzPrivateEndpointConnection -ResourceId $Item.PrivateEndpoint.Id -Force:$true -Confirm:$false -ErrorAction Stop
          $null = Remove-AzPrivateEndpoint -Name $Name -ResourceGroupName $ResourceGroupName -Force:$true -Confirm:$false -ErrorAction Stop
        }
        $EndpointsFin = @(
          Get-AzPrivateEndpointConnection -PrivateLinkResourceId $PrivateLinkResourceId -ErrorAction SilentlyContinue
        )
        if ($EndpointsFin.Count -ne 0) {
          Write-Warning -Message "$($EndpointsFin.Count) private endpoints are still linked to the vault. Remove them for successful vault deletion."
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-RecoveryVaultItems {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $BackupManagementType,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkloadType,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $Vault
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $BackupItems = Get-AzRecoveryServicesBackupItem -BackupManagementType $BackupManagementType -WorkloadType $WorkloadType -VaultId $Vault.ID -ErrorAction SilentlyContinue
      if ($null -ne $BackupItems) {
        $ContainerSoftDelete = $BackupItems | Where-Object { $_.DeleteState -eq 'ToBeDeleted' }
        if ($null -ne $ContainerSoftDelete) {
          foreach ($SoftItem in $ContainerSoftDelete) {
            Write-Output -InputObject "- Undo soft delete of $WorkloadType $($Item.Name) in vault $($Vault.Name)"
            $null = Undo-AzRecoveryServicesBackupItemDeletion -Item $SoftItem -VaultId $Vault.ID -Force:$true -ErrorAction SilentlyContinue
          }
        }
        foreach ($Item in $BackupItems) {
          Write-Output -InputObject "- Unregister $WorkloadType $($Item.Name) from vault $($Vault.Name)"
          $null = Disable-AzRecoveryServicesBackupProtection -Item $Item -VaultId $Vault.ID -RemoveRecoveryPoints -Force:$true -Confirm:$false -ErrorAction Stop
        }
        $BackupItemsFin = @(
          Get-AzRecoveryServicesBackupItem -BackupManagementType $BackupManagementType -WorkloadType $WorkloadType -VaultId $Vault.ID -ErrorAction SilentlyContinue
        )
        if ($BackupItemsFin.Count -ne 0) {
          Write-Warning -Message "$($BackupItemsFin.Count) $WorkloadType backups are still present in the vault. Remove them for successful vault deletion."
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-RecoveryVaultContainers {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ContainerType,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $Vault
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $BackupContainers = Get-AzRecoveryServicesBackupContainer -ContainerType $ContainerType -VaultId $Vault.ID -ErrorAction SilentlyContinue
      if ($null -ne $BackupContainers) {
        foreach ($Item in $BackupContainers) {
          Write-Output -InputObject "- Unregister container $($Item.Name) from vault $($Vault.Name)";
          $null = Unregister-AzRecoveryServicesBackupContainer -Container $Item -VaultId $Vault.ID -Force:$true -Confirm:$false -ErrorAction Stop
        }
        $BackupContainersFin = @(
          Get-AzRecoveryServicesBackupContainer -ContainerType $ContainerType -VaultId $Vault.ID -ErrorAction SilentlyContinue
        )
        if ($BackupContainersFin.Count -ne 0) {
          Write-Warning "$($BackupContainersFin.Count) $ContainerType are still registered to the vault. Remove them for successful vault deletion."
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-RecoveryVaultFabric {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $Vault
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $FabricObjects = Get-AzRecoveryServicesAsrFabric -ErrorAction SilentlyContinue
      if ($null -ne $FabricObjects) {
        Write-Output -InputObject "- Delete any ASR items for vault $($Vault.Name)"
        foreach ($FabricObject in $FabricObjects) {
          $ContainerObjects = Get-AzRecoveryServicesAsrProtectionContainer -Fabric $FabricObject -ErrorAction SilentlyContinue
          foreach ($ContainerObject in $ContainerObjects) {
            $ProtectedItems = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $ContainerObject -ErrorAction SilentlyContinue
            foreach ($ProtectedItem in $ProtectedItems) {
              Write-Output -InputObject "- Triggering DisableDR (purge) for item: $($ProtectedItem.Name)"
              $null = Remove-AzRecoveryServicesAsrReplicationProtectedItem -InputObject $ProtectedItem -Force:$true -Confirm:$false -ErrorAction Stop
            }
            $ContainerMappings = Get-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainer $ContainerObject -ErrorAction SilentlyContinue
            foreach ($ContainerMapping in $ContainerMappings) {
              Write-Output -InputObject "- Triggering remove container mapping for item: $($ContainerMapping.Name)"
              $null = Remove-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainerMapping $ContainerMapping -Force:$true -Confirm:$false -ErrorAction Stop
            }
          }
          $NetworkObjects = Get-AzRecoveryServicesAsrNetwork -Fabric $FabricObject -ErrorAction SilentlyContinue
          foreach ($NetworkObject in $NetworkObjects) {
            $PrimaryNetwork = Get-AzRecoveryServicesAsrNetwork -Fabric $FabricObject -FriendlyName $NetworkObject -ErrorAction SilentlyContinue
            $NetworkMappings = Get-AzRecoveryServicesAsrNetworkMapping -Network $PrimaryNetwork -ErrorAction SilentlyContinue
            foreach ($NetworkMappingObject in $NetworkMappings) {
              $NetworkMapping = Get-AzRecoveryServicesAsrNetworkMapping -Name $NetworkMappingObject.Name -Network $PrimaryNetwork -ErrorAction SilentlyContinue
              $null = Remove-AzRecoveryServicesAsrNetworkMapping -InputObject $NetworkMapping -Confirm:$false -ErrorAction Stop
            }
          }
          Write-Output -InputObject "- Triggering remove fabric: $($FabricObject.FriendlyName)"
          $null = Remove-AzRecoveryServicesAsrFabric -InputObject $FabricObject -Force:$true -Confirm:$false -ErrorAction Stop
        }
      }
      $FabricCount = 0
      $ASRProtectedItems = 0
      $ASRPolicyMappings = 0
      $FabricObjects = Get-AzRecoveryServicesAsrFabric -ErrorAction SilentlyContinue
      if ($null -ne $FabricObjects) {
        foreach ($FabricObject in $FabricObjects) {
          $ContainerObjects = Get-AzRecoveryServicesAsrProtectionContainer -Fabric $FabricObject -ErrorAction SilentlyContinue
          foreach ($ContainerObject in $ContainerObjects) {
            $protectedItems = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $ContainerObject -ErrorAction SilentlyContinue
            foreach ($ProtectedItem in $ProtectedItems) {
              $ASRProtectedItems++
            }
            $ContainerMappings = Get-AzRecoveryServicesAsrProtectionContainerMapping -ProtectionContainer $ContainerObject -ErrorAction SilentlyContinue
            foreach ($ContainerMapping in $ContainerMappings) {
              $ASRPolicyMappings++
            }
          }
          $FabricCount++
        }
      }
      if ($FabricCount -ne 0) {
        Write-Warning -Message "$FabricCount ASR fabrics are still present in the vault. Remove them for successful vault deletion."
        if ($ASRProtectedItems -ne 0) {
          Write-Warning -Message "$ASRProtectedItems ASR protected items are still present in the vault. Remove them for successful vault deletion."
        }
        if ($ASRPolicyMappings -ne 0) {
          Write-Warning -Message "$ASRPolicyMappings ASR policy mappings are still present in the vault. Remove them for successful vault deletion."
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-RecoveryVaultServers {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $Vault
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $BackupServers = Get-AzRecoveryServicesBackupManagementServer -VaultId $Vault.ID -ErrorAction SilentlyContinue
      if ($null -ne $BackupServers) {
        foreach ($Item in $backupServersMABS) {
          Write-Output -InputObject "- Unregister management server $($Item.Name) from vault $($Vault.Name)"
          $null = Unregister-AzRecoveryServicesBackupManagementServer -AzureRmBackupManagementServer $Item -VaultId $Vault.ID -Confirm:$false -ErrorAction Stop
        }
        $BackupServersFin = @(
          Get-AzRecoveryServicesBackupManagementServer -VaultId $Vault.ID -ErrorAction SilentlyContinue
        )
        if ($BackupServersFin.Count -ne 0) {
          Write-Warning -Message "$($BackupServersFin.Count) management servers are still registered to the vault. Remove them for successful vault deletion."
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-RecoveryVaultProtectableItems {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    $Vault,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $WorkloadType
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $ProtectableItems = Get-AzRecoveryServicesBackupProtectableItem -WorkloadType $WorkloadType -VaultId $Vault.ID -ErrorAction SilentlyContinue | Where-Object { $_.IsAutoProtected -eq $true }
      if ($null -ne $ProtectableItems) {
        foreach ($Item in $ProtectableItems) {
          Write-Output -InputObject "- Disable auto-protection of $($Item.Name) in vault $($RecoveryVault.Name)"
          $null = Disable-AzRecoveryServicesBackupAutoProtection -BackupManagementType AzureWorkload -WorkloadType $WorkloadType -InputItem $Item -VaultId $RecoveryVault.ID -Confirm:$false -ErrorAction Stop
        }
        $ProtectableItemsFin = @(
          Get-AzRecoveryServicesBackupProtectableItem -WorkloadType $WorkloadType -VaultId $RecoveryVault.ID -ErrorAction SilentlyContinue | Where-Object { $_.IsAutoProtected -eq $true }
        )
        if ($ProtectableItemsFin.Count -ne 0) {
          Write-Warning "$($ProtectableItemsFin.Count) $WorkloadType items are still enabled for auto-protection in the vault. Remove them for successful vault deletion."
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-RecoveryVaults {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $Token = Get-AzAccessToken
      $RestMethodArgs = @{
        Method  = 'Post'
        Uri     = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
        Headers = @{
          Authorization  = "$($Token.Type) $($Token.Token)"
          'Content-type' = 'application/json; charset=utf-8'
        }
        Body    = @{
          query         = "resources | where type =~ 'microsoft.recoveryservices/vaults' and resourceGroup =~ '$ResourceGroupName' | project id, name, resourceGroup"
          options       = @{
            '$top'         = 100
            '$skip'        = 0
            '$skipToken'   = ''
            'resultFormat' = 'objectArray'
          }
          subscriptions = @(
            $SubscriptionId
          )
        } | ConvertTo-Json
      }
      $Response = Invoke-RestMethod @RestMethodArgs
      if (
        $null -ne $Response -and
        [bool]($Response | Get-Member -Name 'data') -and
        $null -ne $Response.data -and
        $Response.data -is [array] -and
        $Response.data.Count -gt 0
      ) {
        foreach ($Vault in $Response.data) {
          $RecoveryVault = Get-AzRecoveryServicesVault -Name $Vault.name -ResourceGroupName $Vault.resourceGroup -ErrorAction Stop
          $null = Set-AzRecoveryServicesAsrVaultContext -Vault $RecoveryVault -ErrorAction SilentlyContinue
          Write-Output -InputObject "- Disable soft delete for vault $($RecoveryVault.Name)"
          $null = Set-AzRecoveryServicesVaultProperty -VaultId $RecoveryVault.ID -SoftDeleteFeatureState Disable -Confirm:$false -ErrorAction Stop
          Write-Output -InputObject "- Disable security features (enhanced security) for vault $($RecoveryVault.Name)"
          $null = Set-AzRecoveryServicesVaultProperty -VaultId $RecoveryVault.ID -DisableHybridBackupSecurityFeature $true -Confirm:$false -ErrorAction Stop
          Remove-RecoveryVaultItems -BackupManagementType 'AzureVM' -WorkloadType 'AzureVM' -Vault $RecoveryVault
          Remove-RecoveryVaultItems -BackupManagementType 'AzureWorkload' -WorkloadType 'MSSQL' -Vault $RecoveryVault
          Remove-RecoveryVaultItems -BackupManagementType 'AzureWorkload' -WorkloadType 'SAPHanaDatabase' -Vault $RecoveryVault
          Remove-RecoveryVaultItems -BackupManagementType 'AzureStorage' -WorkloadType 'AzureFiles' -Vault $RecoveryVault
          Remove-RecoveryVaultItems -BackupManagementType 'MAP' -WorkloadType 'FileFolder' -Vault $RecoveryVault
          Remove-RecoveryVaultContainers -ContainerType 'AzureVM' -Vault $RecoveryVault
          Remove-RecoveryVaultContainers -ContainerType 'AzureVMAppContainer' -Vault $RecoveryVault
          Remove-RecoveryVaultContainers -ContainerType 'AzureStorage' -Vault $RecoveryVault
          Remove-RecoveryVaultContainers -ContainerType 'Windows' -Vault $RecoveryVault
          Remove-RecoveryVaultServers -Vault $RecoveryVault
          Remove-RecoveryVaultProtectableItems -WorkloadType 'MSSQL' -Vault $RecoveryVault
          Remove-RecoveryVaultFabric -Vault $RecoveryVault
          Remove-PrivateEndpoint -PrivateLinkResourceId $RecoveryVault.ID -ResourceGroupName $ResourceGroupName
          $Token = Get-AzAccessToken
          $AuthHeader = @{
            'Content-Type'  = 'application/json'
            'Authorization' = 'Bearer ' + $Token.Token
          }
          $RestUri = "https://management.azure.com//subscriptions/$($SubscriptionId)/resourcegroups/$($ResourceGroupName)/providers/Microsoft.RecoveryServices/vaults/$($RecoveryVault.Name)?api-version=2024-04-01&operation=DeleteVaultUsingPS"
          $null = Invoke-RestMethod -Uri $RestUri -Headers $AuthHeader -Method DELETE
          $VaultDeleted = Get-AzRecoveryServicesVault -Name $RecoveryVault.Name -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
          if ($null -eq $VaultDeleted) {
            Write-Output -InputObject "- Recovery Services Vault $($RecoveryVault.Name) successfully deleted"
          }
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-Resource {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceId,
    [Parameter(Mandatory = $false)]
    [string]
    $Options = '',
    [Parameter(Mandatory = $false)]
    [int]
    $SleepSeconds = 20,
    [Parameter(Mandatory = $false)]
    [string]
    $ApiVersion = '2023-07-01'
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    $Token = Get-AzAccessToken
    if ($ResourceId -notmatch '^/') {
      $ResourceId = "/$($ResourceId)"
    }
    $Uri = $(
      if ($Options -ne '') {
        "https://management.azure.com$($ResourceId)?$($Options)&api-version=$($ApiVersion)"
      } else {
        "https://management.azure.com$($ResourceId)?api-version=$($ApiVersion)"
      }
    )
    $RestMethodArgs = @{
      Uri     = $Uri
      Headers = @{
        Authorization  = "$($Token.Type) $($Token.Token)"
        'Content-type' = 'application/json; charset=utf-8'
      }
      Method  = 'Delete'
    }
    Write-Output -InputObject "- Request removal of $($ResourceId)"
    $i = 0
    $Removed = $false
    while (-not($Removed) -and $i -lt 10) {
      try {
        $null = Invoke-RestMethod @restMethodArgs
        $Removed = $true
      } catch {
        $ErrorMsg = $_.ToString()
        if ($ErrorMsg -match 'Please remove the lock and try again') {
          if ($i -eq 9) {
            Write-Warning -Message $ErrorMsg
          } else {
            Start-Sleep -Seconds $SleepSeconds
          }
          $i++
        } else {
          Write-Warning -Message $ErrorMsg
          break
        }
      }
    }
  }
}
function Remove-ResourceLocks {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $Locks = Get-AzResourceLock -ResourceGroupName $ResourceGroupName -AtScope -ErrorAction Stop
      foreach ($Lock in $Locks) {
        Write-Output -InputObject "- Delete resource lock $($Lock.LockId)";
        $LockRemoved = Remove-AzResourceLock -LockId $Lock.LockId -Force:$true -ErrorAction Stop
        if ($LockRemoved -eq $false) {
          Write-Warning -Message "Failed to remove lock $($Lock.LockId)"
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-StorageImmutabilityPolicy {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    try {
      $StorageAccounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop
      foreach ($StorageAccount in $StorageAccounts) {
        $StorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -UseConnectedAccount -ErrorAction Stop
        $StorageContainers = Get-AzStorageContainer -Context $StorageContext -ErrorAction Stop
        foreach ($StorageContainer in $StorageContainers) {
          $StoragePolicyList = Get-AzRmStorageContainerImmutabilityPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccount.StorageAccountName -ContainerName $StorageContainer.Name -ErrorAction Stop
          foreach ($StoragePolicy in $StoragePolicyList) {
            if ($storagePolicy.State -eq 'Locked') {
              Write-Warning -Message "Storage account $($StorageAccount.StorageAccountName) has a locked immutable storage policy. It cannot be deleted"
            } elseif ($StoragePolicy.State -ne 'Deleted') {
              Write-Output -InputObject "- Delete storage account $($StorageAccount.StorageAccountName) $($StoragePolicy.State) immutable storage policy"
              $StoragePolicyDeleted = Remove-AzRmStorageContainerImmutabilityPolicy -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccount.StorageAccountName -ContainerName $StorageContainer.Name -Etag $StoragePolicy.Etag -Confirm:$false -ErrorAction Stop
              if ($StoragePolicyDeleted.State -ne 'Deleted') {
                Write-Warning -Message "Unable to delete $($StoragePolicyDeleted.Name) immutable storage policy for $($StorageAccount.StorageAccountName). State is $($StoragePolicyDeleted.State)"
              }
            }
          }
        }
      }
    } catch {
      Write-Warning -Message $_.InvocationInfo.PositionMessage
      Write-Warning -Message $_.ToString()
    }
  }
}
function Remove-ResourceGroup {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ResourceGroupName
  )
  begin {
    Set-StrictMode -Version Latest
  }
  process {
    Remove-ResourceLocks -ResourceGroupName $ResourceGroupName
    Remove-OperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName
    Remove-BackupVaults -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    Remove-ImageBuilderTemplates -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    Remove-RecoveryVaults -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName
    Remove-StorageImmutabilityPolicy -ResourceGroupName $ResourceGroupName
    Remove-Resource -ResourceId "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)" -Options 'forceDeletionTypes=Microsoft.Compute/virtualMachines,Microsoft.Compute/virtualMachineScaleSets' -ErrorAction Stop
  }
}

Set-Item -Path Env:\SuppressAzurePowerShellBreakingChangeWarnings 'true' -WhatIf:$false
$Culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $Culture
[System.Threading.Thread]::CurrentThread.CurrentCulture = $Culture
$ErrorActionPreference = 'Stop'
try {
  $AzureConnection = Connect-AzAccount -Identity -WarningAction Ignore
  Write-Verbose -Message "User $($AzureConnection.Context.Account.Id) connected to tenant $($AzureConnection.Context.Tenant.Id)"
} catch {
  Write-Error -Message $_.Exception
}
$Subscriptions = Get-AzSubscription
$RunTime = Get-Date
foreach ($Subscription in $Subscriptions) {
  if ($SubscriptionIgnore -contains $Subscription.Id) {
    continue
  }
  $AzureContext = Set-AzContext -Subscription $Subscription.Id
  $SubscriptionName = $AzureContext.Subscription.Name
  $ResourceGroups = Get-AzResourceGroup
  if ($null -ne $ResourceGroups) {
    foreach ($ResourceGroup in $ResourceGroups) {
      $ResourceGroupName = $ResourceGroup.ResourceGroupName
      $GroupCreated = $(
        if (
          $null -ne $ResourceGroup.Tags -and
          $ResourceGroup.Tags.ContainsKey('CreatedOn') -and
          $ResourceGroup.Tags.CreatedOn -match '^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[1-2]\d|3[0-1])T(?:[0-1]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+|)(?:Z|(?:\+|\-)(?:\d{2}):?(?:\d{2}))$'
        ) {
          [DateTime]::Parse($ResourceGroup.Tags.CreatedOn)
        } else {
          $RunTime.AddDays(-31)
        }
      )
      $DaysAgo = ($RunTime - $GroupCreated).TotalDays.ToString('0.00')
      $DaysToKeep = $(
        try {
          [int]$ResourceGroup.Tags.$DaysToKeepTag
        } catch {
          $DaysToKeepDefault
        }
      )
      if ($DaysToKeep -gt $DaysToKeepMax) {
        $DaysToKeep = $DaysToKeepMax
      }
      $RemoveGroup = $(
        $RunTime -gt $GroupCreated.AddDays($DaysToKeep)
      )
      if ($RemoveGroup) {
        Write-Output -InputObject "Delete resource group $ResourceGroupName in subscription $SubscriptionName (created $DaysAgo days ago)"
        Remove-ResourceGroup -SubscriptionId $Subscription.Id -ResourceGroupName $ResourceGroupName
      } else {
        Write-Output -InputObject "Ignore resource group $ResourceGroupName in subscription $SubscriptionName (created $DaysAgo days ago)"
      }
    }
  }
}
