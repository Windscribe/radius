Radius
=============================

### Documentation
* http://en.wikipedia.org/wiki/RADIUS

### Example
```go
package main

import (
	"fmt"
	"github.com/Windscribe/radius"
)

type radiusService struct{}

func (p radiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
    // a pretty print of the request.
	fmt.Printf("[Authenticate] %s\n", request.String())
	npac := request.Reply()
	switch request.Code {
	case radius.AccessRequest:
		// check username and password
		if request.GetUsername() == "a" && request.GetPassword() == "a" {
			npac.Code = radius.AccessAccept
			// add Vendor-specific attribute - Vendor Cisco (code 9) Attribute h323-remote-address (code 23)
			npac.AddVSA( radius.VSA{Vendor: 9, Type: 23, Value: []byte("10.20.30.40")} )
		} else {
			npac.Code = radius.AccessReject
			npac.AddAVP( radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")} )
		}
	case radius.AccountingRequest:
		// accounting start or end
		npac.Code = radius.AccountingResponse
	default:
		npac.Code = radius.AccessAccept
	}
	return npac
}

func main() {
	s := radius.NewServer(":1812", "secret", radiusService{})

	// or you can convert it to a server that accept request
	// from some host with different secret
	// cls := radius.NewClientList([]radius.Client{
	// 		radius.NewClient("127.0.0.1", "secret1"),
	// 		radius.NewClient("10.10.10.10", "secret2"),
	// })
	// s.WithClientList(cls)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	errChan := make(chan error)
	go func() {
		fmt.Println("waiting for packets...")
		err := s.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()
	select {
	case <-signalChan:
		log.Println("stopping server...")
		s.Stop()
	case err := <-errChan:
		log.Println("[ERR] %v", err.Error())
	}
}
```

### Reference
* EAP MS-CHAPv2 packet format 								http://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
* EAP MS-CHAPv2 											https://tools.ietf.org/html/rfc2759
* RADIUS Access-Request part      							https://tools.ietf.org/html/rfc2865
* RADIUS Accounting-Request part  							https://tools.ietf.org/html/rfc2866
* RADIUS Support For Extensible Authentication Protocol 	https://tools.ietf.org/html/rfc3579
* RADIUS Implementation Issues and Suggested Fixes 			https://tools.ietf.org/html/rfc5080
