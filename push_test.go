package push

import (
	"net/http"
	"strings"
	"testing"
)

type testTransport struct {
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 204,
	}, nil
}

func getStandardEncodedTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BI78AX/4HKDgOFphOWalmcLiql7n/c2VaItwwZFzIT0OGps0Tl1/NRX8syFdRtA+tYI6dBVgGUOgUvD54H2HUDQ",
			Auth:   "cdUHGb0/MZJfNfbf7age6g==",
		},
	}
}

func getURLEncodedTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ",
		},
	}
}

func TestSendNotificationToURLEncodedSubscription(t *testing.T) {
	vapidPrivateKey, vapidPublicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification([]byte("Test"), getURLEncodedTestSubscription(), &Options{
		Transport:       &testTransport{},
		RecordSize:      3070,
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 204 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	vapidPrivateKey, vapidPublicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification([]byte("Test"), getStandardEncodedTestSubscription(), &Options{
		Transport:       &testTransport{},
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: vapidPrivateKey,
		VAPIDPublicKey:  vapidPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 204 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendTooLargeNotification(t *testing.T) {
	vapidPrivateKey, vapidPublicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SendNotification([]byte(strings.Repeat("Test", int(MaxRecordSize))), getStandardEncodedTestSubscription(), &Options{
		Transport:       &testTransport{},
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: vapidPrivateKey,
		VAPIDPublicKey:  vapidPublicKey,
	})
	if err == nil {
		t.Fatalf("Error is nil, expected=%s", ErrMaxPadExceeded)
	}
}
