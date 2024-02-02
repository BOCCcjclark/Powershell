$RealtekDriver = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.FriendlyName -eq "Realtek(R) Audio" }
					
			$NewDriverPath = (Get-WindowsDriver -Online -All | Where-Object Driver -eq "hdaudio.inf").OriginalFileName

			foreach ($Driver in $RealtekDriver) {
			if ($Driver.InfName -ne "hdaudio.inf") {
				Write-Host "Driver is getting updated"

				# Retrieving the associated driver package
				$CurrentDriver = Get-WindowsDriver -Online -All | Where-Object Driver -eq $Driver.InfName

				# Uninstalling current driver
				pnputil.exe /delete-driver $CurrentDriver.OriginalFileName /uninstall

				# Installing new driver
				pnputil.exe /add-driver $NewDriverPath /install
		
				} else {
				Write-Host "Driver is already updated"
				}
}