# Initial ATT MTU response boundary workaround

`BLUEBINDER_FIX_MTU_RESPONSE_PB=1` opts a device into a narrow controller
compatibility workaround. It is disabled by default. Set it through the device's
Bluebinder environment configuration.

On an affected controller, an LSLED badge's first Exchange MTU Response
arrives from `/dev/stpbt` marked as an ACL continuation, despite containing a
complete L2CAP PDU. Linux drops the packet and GATT discovery fails.
The underlying firmware/interoperability cause is not established.

The workaround requires a successful LE connection event, a complete outbound
ATT Exchange MTU Request, and a first inbound ACL packet containing exactly a
complete ATT Exchange MTU Response with MTU 23–517 and no broadcast bits. Only
then is PB=1 changed to PB=2. The actual MTU and payload are preserved. Any prior
inbound ACL fragment disables repair for that connection. Disconnect, successful
controller reset and HAL power-cycle clear the state. Classic links, unknown
handles, normal packets, subsequent replies and genuine fragments are unchanged.
