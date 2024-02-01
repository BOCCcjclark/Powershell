$device = Get-PnpDevice | Where-Object {$_.FriendlyName -like "Speakers (Realtek(R) Audio)"}
Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false
