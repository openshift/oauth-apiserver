package network

import (
	"net/http"
	"sync/atomic"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/klog/v2"
)

type dynamicTransport struct {
	config              *transportConfig
	rebuildRequestCount atomic.Int32
	transport           atomic.Pointer[http.Transport]
}

var _ http.RoundTripper = &dynamicTransport{}
var _ dynamiccertificates.Listener = &dynamicTransport{}

func (t *dynamicTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.transport.Load().RoundTrip(request)
}

func (t *dynamicTransport) CloseIdleConnections() {
	t.transport.Load().CloseIdleConnections()
}

func (t *dynamicTransport) Enqueue() {
	if t.rebuildRequestCount.Add(1) > 1 {
		return
	}
	// This loop causes a transport rebuild per enqueue request. There are no bursts.
	// This is fine since the probability of multiple change notifications colliding is extremely low anyway.
	for {
		t.rebuild()
		if t.rebuildRequestCount.Add(-1) == 0 {
			break
		}
	}
}

func (t *dynamicTransport) rebuild() {
	transport, err := t.config.newHTTPTransport()
	if err != nil {
		klog.ErrorS(err, "Unable to rebuild outbound HTTP transport after CA content changed; continuing with the last known-good transport")
		return
	}

	oldTransport := t.transport.Swap(transport)
	if oldTransport != nil {
		oldTransport.CloseIdleConnections()
	}
	klog.V(2).InfoS("Rebuilt outbound HTTP transport after CA content changed")
}
