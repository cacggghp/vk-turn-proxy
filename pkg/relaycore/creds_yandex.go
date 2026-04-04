// SPDX-License-Identifier: GPL-3.0-only

package relaycore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const defaultBrowserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

type yandexCredentialProvider struct{}

func NewYandexCredentialProvider() CredentialProvider {
	return CredentialProviderFunc(func(ctx context.Context, inviteLink string) (TurnCredentials, error) {
		return (&yandexCredentialProvider{}).GetCredentials(ctx, inviteLink)
	})
}

func (p *yandexCredentialProvider) GetCredentials(ctx context.Context, inviteLink string) (TurnCredentials, error) {
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf(
		"%s%s%s",
		"/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F",
		inviteLink,
		"/connection?next_gen_media_platform_allowed=false",
	)
	profile := getRandomProfile()
	userAgent := profile.UserAgent
	name := generateName()

	type conferenceResponse struct {
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	type partMeta struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
		SendAudio   bool   `json:"sendAudio"`
		SendVideo   bool   `json:"sendVideo"`
	}

	type partAttrs struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
	}

	type sdkInfo struct {
		Implementation string `json:"implementation"`
		Version        string `json:"version"`
		UserAgent      string `json:"userAgent"`
		HwConcurrency  int    `json:"hwConcurrency"`
	}

	type capabilities struct {
		OfferAnswerMode             []string `json:"offerAnswerMode"`
		InitialSubscriberOffer      []string `json:"initialSubscriberOffer"`
		SlotsMode                   []string `json:"slotsMode"`
		SimulcastMode               []string `json:"simulcastMode"`
		SelfVadStatus               []string `json:"selfVadStatus"`
		DataChannelSharing          []string `json:"dataChannelSharing"`
		VideoEncoderConfig          []string `json:"videoEncoderConfig"`
		DataChannelVideoCodec       []string `json:"dataChannelVideoCodec"`
		BandwidthLimitationReason   []string `json:"bandwidthLimitationReason"`
		SdkDefaultDeviceManagement  []string `json:"sdkDefaultDeviceManagement"`
		JoinOrderLayout             []string `json:"joinOrderLayout"`
		PinLayout                   []string `json:"pinLayout"`
		SendSelfViewVideoSlot       []string `json:"sendSelfViewVideoSlot"`
		ServerLayoutTransition      []string `json:"serverLayoutTransition"`
		SdkPublisherOptimizeBitrate []string `json:"sdkPublisherOptimizeBitrate"`
		SdkNetworkLostDetection     []string `json:"sdkNetworkLostDetection"`
		SdkNetworkPathMonitor       []string `json:"sdkNetworkPathMonitor"`
		PublisherVp9                []string `json:"publisherVp9"`
		SvcMode                     []string `json:"svcMode"`
		SubscriberOfferAsyncAck     []string `json:"subscriberOfferAsyncAck"`
		SvcModes                    []string `json:"svcModes"`
		ReportTelemetryModes        []string `json:"reportTelemetryModes"`
		KeepDefaultDevicesModes     []string `json:"keepDefaultDevicesModes"`
	}

	type helloPayload struct {
		ParticipantMeta        partMeta     `json:"participantMeta"`
		ParticipantAttributes  partAttrs    `json:"participantAttributes"`
		SendAudio              bool         `json:"sendAudio"`
		SendVideo              bool         `json:"sendVideo"`
		SendSharing            bool         `json:"sendSharing"`
		ParticipantID          string       `json:"participantId"`
		RoomID                 string       `json:"roomId"`
		ServiceName            string       `json:"serviceName"`
		Credentials            string       `json:"credentials"`
		CapabilitiesOffer      capabilities `json:"capabilitiesOffer"`
		SdkInfo                sdkInfo      `json:"sdkInfo"`
		SdkInitializationID    string       `json:"sdkInitializationId"`
		DisablePublisher       bool         `json:"disablePublisher"`
		DisableSubscriber      bool         `json:"disableSubscriber"`
		DisableSubscriberAudio bool         `json:"disableSubscriberAudio"`
	}

	type helloRequest struct {
		UID   string       `json:"uid"`
		Hello helloPayload `json:"hello"`
	}

	type flexURLs []string

	type wssResponse struct {
		ServerHello struct {
			RtcConfiguration struct {
				IceServers []struct {
					Urls       flexURLs `json:"urls"`
					Username   string   `json:"username,omitempty"`
					Credential string   `json:"credential,omitempty"`
				} `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	type wssAck struct {
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type wssData struct {
		ParticipantID string
		RoomID        string
		Credentials   string
		WSS           string
	}

	endpoint := "https://" + telemostConfHost + telemostConfPath
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return TurnCredentials{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return TurnCredentials{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return TurnCredentials{}, fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(body))
	}

	var result conferenceResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return TurnCredentials{}, fmt.Errorf("decode conf: %w", err)
	}
	data := wssData{
		ParticipantID: result.PeerID,
		RoomID:        result.RoomID,
		Credentials:   result.Credentials,
		WSS:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)

	wsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(wsCtx, data.WSS, h)
	if err != nil {
		return TurnCredentials{}, fmt.Errorf("ws dial: %w", err)
	}
	defer conn.Close()

	req1 := helloRequest{
		UID: uuid.New().String(),
		Hello: helloPayload{
			ParticipantMeta: partMeta{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
				SendAudio:   false,
				SendVideo:   false,
			},
			ParticipantAttributes: partAttrs{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
			},
			SendAudio:   false,
			SendVideo:   false,
			SendSharing: false,

			ParticipantID: data.ParticipantID,
			RoomID:        data.RoomID,
			ServiceName:   "telemost",
			Credentials:   data.Credentials,
			SdkInfo: sdkInfo{
				Implementation: "browser",
				Version:        "5.15.0",
				UserAgent:      userAgent,
				HwConcurrency:  4,
			},
			SdkInitializationID:    uuid.New().String(),
			DisablePublisher:       false,
			DisableSubscriber:      false,
			DisableSubscriberAudio: false,
			CapabilitiesOffer: capabilities{
				OfferAnswerMode:             []string{"SEPARATE"},
				InitialSubscriberOffer:      []string{"ON_HELLO"},
				SlotsMode:                   []string{"FROM_CONTROLLER"},
				SimulcastMode:               []string{"DISABLED"},
				SelfVadStatus:               []string{"FROM_SERVER"},
				DataChannelSharing:          []string{"TO_RTP"},
				VideoEncoderConfig:          []string{"NO_CONFIG"},
				DataChannelVideoCodec:       []string{"VP8"},
				BandwidthLimitationReason:   []string{"BANDWIDTH_REASON_DISABLED"},
				SdkDefaultDeviceManagement:  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				JoinOrderLayout:             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				PinLayout:                   []string{"PIN_LAYOUT_DISABLED"},
				SendSelfViewVideoSlot:       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				ServerLayoutTransition:      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				SdkPublisherOptimizeBitrate: []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				SdkNetworkLostDetection:     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				SdkNetworkPathMonitor:       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				PublisherVp9:                []string{"PUBLISH_VP9_DISABLED"},
				SvcMode:                     []string{"SVC_MODE_DISABLED"},
				SubscriberOfferAsyncAck:     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				SvcModes:                    []string{"FALSE"},
				ReportTelemetryModes:        []string{"TRUE"},
				KeepDefaultDevicesModes:     []string{"TRUE"},
			},
		},
	}

	if err := conn.WriteJSON(req1); err != nil {
		return TurnCredentials{}, fmt.Errorf("ws write: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return TurnCredentials{}, fmt.Errorf("ws set read deadline: %w", err)
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return TurnCredentials{}, fmt.Errorf("ws read: %w", err)
		}

		var ack wssAck
		if err := json.Unmarshal(msg, &ack); err == nil && ack.Ack.Status.Code != "" {
			continue
		}

		var wsResp wssResponse
		if err := json.Unmarshal(msg, &wsResp); err == nil {
			ice := wsResp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

					return TurnCredentials{
						Username: s.Username,
						Password: s.Credential,
						Address:  address,
					}, nil
				}
			}
		}
	}
}
