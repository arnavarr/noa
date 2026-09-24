// Generador del golden de ConnInspect (rebanada qw-dg1-conninspect de noa-sdk).
//
// Captura vectores EJECUTANDO el oraculo:
//   - github.com/openziti/sdk-golang @ pin 4b6a087e92faaf94fcb027e9008bbcf45a325225
//     (ziti/edge.NewConnInspectResponse, ziti/edge.ConnType*)
//   - github.com/openziti/channel/v4 @ v4.3.9 (Message.ReplyTo, MarshalV2)
//
// El oraculo se toma del modulo publico sdk-golang v1.7.0 (el tag apunta al pin 4b6a087; go.sum lo fija).
package main

import (

	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
)

type HeaderEntry struct {
	Key      int32  `json:"key"`
	ValueHex string `json:"value_hex"`
}

type MsgSnapshot struct {
	ContentType int32         `json:"content_type"`
	Sequence    int32         `json:"sequence"`
	ReplyFor    int32         `json:"reply_for"`
	IsReply     bool          `json:"is_reply"`
	Headers     []HeaderEntry `json:"headers"`
	BodyHex     string        `json:"body_hex"`
	BodyUTF8    string        `json:"body_utf8"`
}

type Vector struct {
	ID   string `json:"id"`
	Desc string `json:"desc"`
	// Sede del oraculo que este vector reproduce.
	OracleSite string `json:"oracle_site"`

	Request  MsgSnapshot `json:"request"`
	Response MsgSnapshot `json:"response"`

	// Bytes de wire REALES emitidos por channel.MarshalV2 sobre la respuesta.
	// El ORDEN de los headers dentro de la seccion de headers NO es
	// determinista (marshalHeaders itera un map[int32][]byte), asi que se
	// publican TODAS las formas distintas observadas, ordenadas por hex.
	WireV2Forms []string `json:"wire_v2_forms"`
	WireV2Len   int      `json:"wire_v2_len"`
	NMarshals   int      `json:"n_marshals"`

	// Claves del request que SOBREVIVIERON al reflejo de ReplyTo (medido).
	//
	// ⚠ Este par se computa sobre el response REAL, cuyo constructor ya puso
	// ConnId y ConnType: una clave que el constructor pone con el MISMO valor
	// que trae el request es indistinguible de una reflejada. Para el conjunto
	// del predicado, usa ReflectProbeKeys (abajo), que NO tiene esa ambiguedad.
	ReflectedFromRequest []int32 `json:"reflected_from_request_ambiguous"`
	DroppedFromRequest   []int32 `json:"dropped_from_request_ambiguous"`

	// SONDA DE REFLEJO PURO: un mensaje SIN headers propios al que se le
	// aplica el MISMO ReplyTo(request). Toda clave presente aqui viene
	// EXCLUSIVAMENTE del reflejo, asi que este es el conjunto que define el
	// predicado (message.go:394) sin colapsar causas.
	ReflectProbeKeys    []int32 `json:"reflect_probe_keys"`
	ReflectProbeDropped []int32 `json:"reflect_probe_dropped"`
}

type Golden struct {
	Schema    string            `json:"schema"`
	Generator string            `json:"generator"`
	Oracle    map[string]string `json:"oracle"`
	Constants map[string]int64  `json:"constants"`
	Notes     []string          `json:"notes"`
	Vectors   []Vector          `json:"vectors"`
}

func snapshot(m *channel.Message) MsgSnapshot {
	keys := make([]int32, 0, len(m.Headers))
	for k := range m.Headers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	hs := make([]HeaderEntry, 0, len(keys))
	for _, k := range keys {
		hs = append(hs, HeaderEntry{Key: k, ValueHex: hex.EncodeToString(m.Headers[k])})
	}
	return MsgSnapshot{
		ContentType: m.ContentType,
		Sequence:    m.Sequence(),
		ReplyFor:    m.ReplyFor(),
		IsReply:     m.IsReply(),
		Headers:     hs,
		BodyHex:     hex.EncodeToString(m.Body),
		BodyUTF8:    string(m.Body),
	}
}

// marshalAndMeasure serializa N veces el MISMO mensaje y devuelve TODAS las
// formas de wire distintas que produce, ORDENADAS por hex (el orden de los
// headers depende del recorrido del map, que Go aleatoriza).
func marshalAndMeasure(m *channel.Message, n int) (forms []string, err error) {
	set := map[string]bool{}
	for i := 0; i < n; i++ {
		b, e := channel.MarshalV2(m)
		if e != nil {
			return nil, e
		}
		set[hex.EncodeToString(b)] = true
	}
	for k := range set {
		forms = append(forms, k)
	}
	sort.Strings(forms)
	return forms, nil
}

// keysOf devuelve las claves de un mapa de headers, ordenadas.
func keysOf(h channel.Headers) []int32 {
	ks := make([]int32, 0, len(h))
	for k := range h {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i] < ks[j] })
	return ks
}

func buildVector(id, desc, site string, req *channel.Message, resp *channel.Message, respSeq int32) Vector {
	// Claves del request ANTES de reflejar, y del response ANTES de reflejar.
	reqKeys := keysOf(req.Headers)
	preRespKeys := map[int32]bool{}
	for _, k := range keysOf(resp.Headers) {
		preRespKeys[k] = true
	}

	reqSnap := snapshot(req)

	// El oraculo hace SIEMPRE: resp.ReplyTo(msg).Send(...)
	resp.ReplyTo(req)
	// El canal asigna el sequence al enviar (senders.go:31 / impl.go:257,
	// ctx.NextSequence()); aqui se fija a un valor conocido para que el vector
	// sea reproducible.
	resp.SetSequence(respSeq)

	// Que claves del request sobrevivieron.
	var reflected, dropped []int32
	for _, k := range reqKeys {
		if _, present := resp.Headers[k]; present {
			// Presente en el response: reflejada, salvo que ya la pusiera el
			// constructor con su propio valor.
			if preRespKeys[k] {
				// Colision: solo cuenta como reflejada si el VALOR cambio al
				// del request.
				if hex.EncodeToString(resp.Headers[k]) == hex.EncodeToString(req.Headers[k]) {
					reflected = append(reflected, k)
				} else {
					dropped = append(dropped, k)
				}
			} else {
				reflected = append(reflected, k)
			}
		} else {
			dropped = append(dropped, k)
		}
	}
	if reflected == nil {
		reflected = []int32{}
	}
	if dropped == nil {
		dropped = []int32{}
	}

	// Sonda de reflejo PURO: mensaje sin headers propios + el MISMO ReplyTo.
	probe := channel.NewMessage(edge.ContentTypeConnInspectResponse, nil)
	probe.ReplyTo(req)
	probeKeys := keysOf(probe.Headers)
	probeSet := map[int32]bool{}
	for _, k := range probeKeys {
		probeSet[k] = true
	}
	var probeDropped []int32
	for _, k := range reqKeys {
		if !probeSet[k] {
			probeDropped = append(probeDropped, k)
		}
	}
	if probeDropped == nil {
		probeDropped = []int32{}
	}

	const nMarshals = 200
	forms, err := marshalAndMeasure(resp, nMarshals)
	if err != nil {
		panic(err)
	}

	return Vector{
		ID:                           id,
		Desc:                         desc,
		OracleSite:                   site,
		Request:                      reqSnap,
		Response:                     snapshot(resp),
		WireV2Forms:                  forms,
		WireV2Len:                    len(forms[0]) / 2,
		NMarshals:                    nMarshals,
		ReflectedFromRequest:         reflected,
		DroppedFromRequest:           dropped,
		ReflectProbeKeys:             probeKeys,
		ReflectProbeDropped:          probeDropped,
	}
}

// newRequest construye un ConnInspectRequest (60798) como lo emite un peer.
func newRequest(seq int32, headers map[int32][]byte) *channel.Message {
	m := channel.NewMessage(edge.ContentTypeConnInspectRequest, nil)
	for k, v := range headers {
		m.Headers[k] = v
	}
	m.SetSequence(seq)
	return m
}

func main() {
	g := Golden{
		Schema:    "noa-sdk/conninspect-golden/v1",
		Generator: "qw-dg1-conninspect goldengen (Go 1.26.3)",
		Oracle: map[string]string{
			"sdk_golang_pin":     "4b6a087e92faaf94fcb027e9008bbcf45a325225",
			"sdk_golang_version": "v1.7.0",
			"channel_version":    "v4.3.9",
			"responder_invalid":  "ziti/edge/msg_mux.go:402-409",
			"responder_dial":     "ziti/edge/network/conn.go:303-310",
			"responder_bind":     "ziti/edge/network/hosting_conn.go:192-199",
			"constructor":        "ziti/edge/messages.go:264-269",
			"reply_to":           "channel/v4@v4.3.9/message.go:390-399",
			"marshal":            "channel/v4@v4.3.9/message.go:583-633",
		},
		Constants: map[string]int64{
			"ContentTypeConnInspectRequest":  int64(edge.ContentTypeConnInspectRequest),
			"ContentTypeConnInspectResponse": int64(edge.ContentTypeConnInspectResponse),
			"ConnIdHeader":                   int64(edge.ConnIdHeader),
			"ConnTypeHeader":                 int64(edge.ConnTypeHeader),
			"ConnTypeInvalid":                int64(edge.ConnTypeInvalid),
			"ConnTypeDial":                   int64(edge.ConnTypeDial),
			"ConnTypeBind":                   int64(edge.ConnTypeBind),
			"ConnTypeUnknown":                int64(edge.ConnTypeUnknown),
			"ReflectedHeaderBitMask":         int64(channel.ReflectedHeaderBitMask),
			"MaxReflectedHeader":             int64(channel.MaxReflectedHeader),
			"ReplyForHeader":                 int64(channel.ReplyForHeader),
			"HelloSequence":                  int64(channel.HelloSequence),
		},
		Notes: []string{
			"El ORDEN de los headers en el wire NO es determinista en el oraculo: marshalHeaders (message.go:635-653) itera un map[int32][]byte. wire_v2_sample_hex es UNA muestra valida; la equivalencia se afirma sobre el PLANO OBSERVABLE (content_type, sequence, reply_for, conjunto de headers, body), no sobre la secuencia de bytes.",
			"MarshalV2 escribe ReplyForHeader (1) en tiempo de marshal desde m.replyFor (message.go:604-606), MUTANDO el mensaje. El snapshot del response se toma DESPUES del marshal, asi que 'headers' incluye la clave 1 con el sequence del request en uint32 LE: es exactamente el conjunto que viaja al wire. El campo 'reflected_from_request' se computa ANTES del marshal.",
			"El sequence del response lo asigna el canal al enviar (senders.go:31, impl.go:257: ctx.NextSequence()); NewMessage lo deja en -1 (message.go:324), que es el valor de HelloSequence (channel.go:210).",
			"REPRODUCIBILIDAD MEDIDA (no supuesta): el PLANO OBSERVABLE es reproducible (3 ejecuciones del generador, sha256 del plano canonico IDENTICO); el bloque wire_v2_forms NO lo es (5 ejecuciones, 4 sha256 distintos del fichero completo): Go aleatoriza el recorrido del map por PROCESO, asi que ni la muestra ni el CONJUNTO de rotaciones observadas son estables. Por eso wire_v2_forms es una MUESTRA CONGELADA en la captura que se commitea, y la re-derivacion del golden se verifica comparando el PLANO CANONICO, nunca el fichero byte a byte.",
			"Uso previsto de wire_v2_forms: son bytes REALES del oraculo (el extremo del oraculo que exige RB-6 ampliada). El port debe DECODIFICAR cada forma y obtener el plano observable pineado; no se le exige EMITIR ninguna forma concreta, porque el orden de headers no es parte del contrato (unmarshalHeaders, message.go:559-580, acepta cualquier orden).",
		},
	}

	// ---- Grupo A: los TRES desenlaces del respondedor ----

	// V1: conn desconocida. Reproduce msg_mux.go:404 literalmente.
	{
		connId := uint32(4242)
		req := newRequest(7, map[int32][]byte{
			edge.ConnIdHeader: u32le(connId),
		})
		resp := edge.NewConnInspectResponse(connId, edge.ConnTypeInvalid,
			fmt.Sprintf("invalid conn id [%v]", connId))
		g.Vectors = append(g.Vectors, buildVector(
			"V1-invalid-conn",
			"conn id desconocida: ConnTypeInvalid + body 'invalid conn id [N]'",
			"ziti/edge/msg_mux.go:402-409",
			req, resp, 42))
	}

	// V2: conn de dial viva. ConnTypeDial; el body lo produce conn.Inspect()
	// (network/conn.go:277-289, 9 claves). Aqui se usa el cuerpo reducido de la
	// ventana declarada del arco (D-n del spec).
	{
		connId := uint32(7)
		req := newRequest(11, map[int32][]byte{
			edge.ConnIdHeader: u32le(connId),
		})
		resp := edge.NewConnInspectResponse(connId, edge.ConnTypeDial, `{"id":7}`)
		g.Vectors = append(g.Vectors, buildVector(
			"V2-dial-conn",
			"conn de dial viva: ConnTypeDial (body reducido por la ventana del arco)",
			"ziti/edge/network/conn.go:303-310 (constructor); cuerpo: conn.go:277-289",
			req, resp, 43))
	}

	// V3: conn de bind viva. ConnTypeBind; cuerpo real en
	// network/hosting_conn.go:247-260 (4 claves + listener con 4).
	{
		connId := uint32(9)
		req := newRequest(12, map[int32][]byte{
			edge.ConnIdHeader: u32le(connId),
		})
		resp := edge.NewConnInspectResponse(connId, edge.ConnTypeBind, `{"id":9}`)
		g.Vectors = append(g.Vectors, buildVector(
			"V3-bind-conn",
			"conn de bind viva: ConnTypeBind (body reducido por la ventana del arco)",
			"ziti/edge/network/hosting_conn.go:192-199 (constructor); cuerpo: hosting_conn.go:247-260",
			req, resp, 44))
	}

	// ---- Grupo B: las fronteras del reflejo de ReplyTo ----

	// V4: TODAS las fronteras en UN SOLO request.
	//  127  -> bit 7 apagado                      => NO refleja
	//  128  -> bit 7 encendido, <= 255            => refleja
	//  255  -> bit 7 encendido, == techo          => refleja
	//  256  -> bit 7 apagado (0b1_0000_0000)      => NO refleja  (mutacion <=255 -> <=256 es NO-OP)
	//   -1  -> int32 negativo, bit 7 encendido    => refleja
	// -129  -> int32 negativo, bit 7 apagado      => NO refleja
	//  384  -> bit 7 encendido y > 255            => NO refleja  (separa el TECHO)
	// 1022  -> ConnTypeHeader REAL: bit 7 y > 255 => NO refleja  (bajo techo roto pisaria el ConnType)
	{
		connId := uint32(4242)
		req := newRequest(101, map[int32][]byte{
			edge.ConnIdHeader:  u32le(connId),
			127:                []byte{0x7f},
			128:                []byte("uuid-128"),
			255:                []byte{0xff},
			256:                []byte{0x01, 0x00},
			-1:                 []byte{0xde, 0xad},
			-129:               []byte{0xbe, 0xef},
			384:                []byte{0x80, 0x01},
			edge.ConnTypeHeader: []byte{0x03}, // ConnTypeUnknown: si el techo se rompe, PISA el ConnType
		})
		resp := edge.NewConnInspectResponse(connId, edge.ConnTypeInvalid,
			fmt.Sprintf("invalid conn id [%v]", connId))
		g.Vectors = append(g.Vectors, buildVector(
			"V4-reflect-all-frontiers",
			"fronteras del reflejo en UN request: 127/128/255/256, -1/-129, 384 y 1022 (ConnType real)",
			"channel/v4@v4.3.9/message.go:390-399",
			req, resp, 45))
	}

	// V5: request SIN headers reflejables (control negativo del reflejo).
	{
		connId := uint32(1)
		req := newRequest(200, map[int32][]byte{
			edge.ConnIdHeader: u32le(connId),
		})
		resp := edge.NewConnInspectResponse(connId, edge.ConnTypeInvalid,
			fmt.Sprintf("invalid conn id [%v]", connId))
		g.Vectors = append(g.Vectors, buildVector(
			"V5-no-reflectable-headers",
			"control negativo: ningun header del request cruza el predicado",
			"channel/v4@v4.3.9/message.go:390-399",
			req, resp, 46))
	}

	// V6: el request llega con sequence NEGATIVO distinto de -1 y con 128 vivo
	// (control de que reply_for copia el sequence tal cual).
	{
		connId := uint32(65535)
		req := newRequest(-7, map[int32][]byte{
			edge.ConnIdHeader: u32le(connId),
			128:               []byte("trace-uuid"),
		})
		resp := edge.NewConnInspectResponse(connId, edge.ConnTypeInvalid,
			fmt.Sprintf("invalid conn id [%v]", connId))
		g.Vectors = append(g.Vectors, buildVector(
			"V6-negative-sequence",
			"reply_for copia el sequence del request tal cual, incluso negativo",
			"channel/v4@v4.3.9/message.go:390-399",
			req, resp, 47))
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		panic(err)
	}
}

func u32le(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}
