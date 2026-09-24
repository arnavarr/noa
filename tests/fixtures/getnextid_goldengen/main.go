// Generador del golden de GetNextId (rebanada qw-getnextid-clamp de noa-sdk).
//
// Captura vectores EJECUTANDO el oraculo:
//   - github.com/openziti/sdk-golang @ pin 4b6a087e92faaf94fcb027e9008bbcf45a325225
//     (ziti/edge.NewChannelConnMapMux, ConnMuxImpl.GetNextId, ConnMuxImpl.Add)
//   - github.com/openziti/channel/v4 @ v4.3.9 (solo el tipo Message del interfaz MsgSink)
//
// El oraculo se toma del modulo publico sdk-golang v1.7.0 (el tag apunta al pin 4b6a087; go.sum lo fija). El generador NO reimplementa
// nada del algoritmo: solo SIEMBRA el campo privado `nextId` (inalcanzable de otro modo:
// desde fuera del paquete la rama de REBOBINADO exigiria ~2^31 llamadas) y registra sinks
// para sembrar el predicado "en uso". `minId`/`maxId`/`id`/`nextId` de salida se CAPTURAN.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"unsafe"

	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
)

// probeSink es el MsgSink minimo que `mux.Add` exige (ziti/edge/msg_mux.go:48-140).
type probeSink struct{ id uint32 }

func (s *probeSink) Id() uint32                     { return s.id }
func (s *probeSink) AcceptMessage(*channel.Message) {}
func (s *probeSink) HandleMuxClose() error          { return nil }
func (s *probeSink) GetData() any                   { return nil }
func (s *probeSink) SetData(any)                    {}

// field devuelve un *uint32 al campo PRIVADO `name` de *ConnMuxImpl[any].
// Es la unica via de siembra: los tres campos (nextId/minId/maxId) son minusculas.
func field(mux *edge.ConnMuxImpl[any], name string) *uint32 {
	v := reflect.ValueOf(mux).Elem().FieldByName(name)
	if !v.IsValid() {
		panic("campo inexistente en ConnMuxImpl: " + name)
	}
	return (*uint32)(unsafe.Pointer(v.UnsafeAddr()))
}

type Cell struct {
	ID   string `json:"id"`
	Desc string `json:"desc"`
	// SEMBRADO por el generador.
	SeedNextID uint32   `json:"seed_next_id"`
	InUse      []uint32 `json:"in_use"`
	// CAPTURADO del oraculo.
	MinID       uint32 `json:"min_id"`
	MaxID       uint32 `json:"max_id"`
	ReturnedID  uint32 `json:"returned_id"`
	NextIDAfter uint32 `json:"next_id_after"`
}

type Golden struct {
	Schema     string            `json:"schema"`
	Generator  string            `json:"generator"`
	Oracle     map[string]string `json:"oracle"`
	Provenance map[string]string `json:"provenance"`
	Cells      []Cell            `json:"cells"`
}

func main() {
	maxId := uint32(math.MaxUint32/2) - 1 // 2147483646 = 2^31-2 (msg_mux.go:302)
	specs := []struct {
		id, desc string
		seed     uint32
		inUse    []uint32
	}{
		{"C-01", "arranque en frio: el contador es 0, la primera asignacion es 1", 0, nil},
		{"C-02", "segunda asignacion consecutiva", 1, nil},
		{"C-03", "SKIP simple: el id que tocaba esta en uso", 0, []uint32{1}},
		{"C-04", "SKIP multiple: fixture multi-elemento, 1 y 2 en uso, ORDEN 1 luego 2", 0, []uint32{1, 2}},
		{"C-05", "frontera INFERIOR del rebobinado: devuelve maxId-1, el ULTIMO id valido", maxId - 2, nil},
		{"C-06", "frontera SUPERIOR: el candidato es maxId EXACTO y REBOBINA a minId", maxId - 1, nil},
		{"C-07", "por encima de maxId: REBOBINA", maxId, nil},
		{"C-08", "candidato == MaxUint32: REBOBINA", math.MaxUint32 - 1, nil},
		{"C-09", "WRAPAROUND del u32: el contador ya vale MaxUint32, el candidato es 0 y 0 esta EN RANGO", math.MaxUint32, nil},
		{"C-10", "REBOBINA y ADEMAS salta: tras rebobinar, el 1 esta en uso", maxId - 1, []uint32{1}},
		{"C-11", "id EN USO en la frontera: maxId-1 ocupado, salta, sale de rango y REBOBINA", maxId - 2, []uint32{maxId - 1}},
		{"C-12", "0 en uso no cambia nada: el 0 nunca es candidato salvo wraparound", 0, []uint32{0}},
		// C-13 es la UNICA celda que separa el ORDEN de las ramas (i) y (ii) del bucle: es la unica
		// que instancia EN-USO *y* FUERA-DE-RANGO a la vez sobre el mismo candidato. Con el orden
		// REAL (i antes que ii) el candidato MaxUint32 esta en uso => salta => el Add ENVUELVE a 0,
		// que esta libre y en rango => devuelve 0. Con el orden INVERTIDO (ii antes que i) el mismo
		// candidato sale de rango => rebobina a minId => devuelve 1. Sin ella, la "mutacion asesina"
		// de T-1 era VACUA: ninguna de las 12 celdas anteriores distingue los dos ordenes.
		{"C-13", "SEPARADORA del ORDEN (i) vs (ii): MaxUint32 en uso Y fuera de rango a la vez", math.MaxUint32 - 1, []uint32{math.MaxUint32}},
	}

	g := Golden{
		Schema:    "noa-sdk/getnextid-golden/v1",
		Generator: fmt.Sprintf("qw-getnextid-clamp goldengen (%s)", goVersion()),
		Oracle: map[string]string{
			"sdk_version": "v1.7.0",
			"pin":         "4b6a087e92faaf94fcb027e9008bbcf45a325225",
			"constructor": "ziti/edge/msg_mux.go:300-309",
			"fields":      "ziti/edge/msg_mux.go:311-318",
			"get_next_id": "ziti/edge/msg_mux.go:337-352",
			"add":         "ziti/edge/msg_mux.go:474-483",
			"caller_host": "ziti/edge/network/hosting_conn.go:294",
			"caller_dial": "ziti/edge/network/factory.go:118",
			"caller_bind": "ziti/edge/network/factory.go:179",
		},
		Provenance: map[string]string{
			"seed_next_id":  "SEMBRADO (el generador escribe el campo privado nextId)",
			"in_use":        "SEMBRADO (el generador registra sinks con mux.Add)",
			"min_id":        "CAPTURADO (leido del mux DESPUES del constructor: nunca se escribe)",
			"max_id":        "CAPTURADO (leido del mux DESPUES del constructor)",
			"returned_id":   "CAPTURADO (valor de retorno de GetNextId)",
			"next_id_after": "CAPTURADO (campo privado nextId tras la llamada)",
		},
	}

	for _, s := range specs {
		mux := edge.NewChannelConnMapMux[any](nil).(*edge.ConnMuxImpl[any])
		*field(mux, "nextId") = s.seed
		for _, u := range s.inUse {
			if err := mux.Add(&probeSink{id: u}); err != nil {
				panic(fmt.Sprintf("%s: Add(%d): %v", s.id, u, err))
			}
		}
		got := mux.GetNextId()
		inUse := s.inUse
		if inUse == nil {
			inUse = []uint32{}
		}
		g.Cells = append(g.Cells, Cell{
			ID: s.id, Desc: s.desc,
			SeedNextID: s.seed, InUse: inUse,
			MinID:       *field(mux, "minId"),
			MaxID:       *field(mux, "maxId"),
			ReturnedID:  got,
			NextIDAfter: *field(mux, "nextId"),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		panic(err)
	}
}

func goVersion() string { return "Go 1.26.3" }
