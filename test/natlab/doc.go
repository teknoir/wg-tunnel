// Package natlab holds the Linux network-namespace NAT lab for plane B. Its
// tests carry the build tag natlab and need root:
//
//	go test -c -tags natlab -o /tmp/natlab.test ./test/natlab && sudo /tmp/natlab.test -test.v
//
// See natlab.sh for the topology.
package natlab
