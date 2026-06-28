module example.com/app

go 1.21

require (
	example.com/vuln v1.0.0
	example.com/safe v2.0.0
)

require example.com/indirectvuln v0.5.0 // indirect
