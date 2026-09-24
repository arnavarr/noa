//! Adaptador del `TcpStream` de netstack-smoltcp con **half-close ACOTADO** (M2a del arco intercept,
//! superface (C) — sin oráculo Ziti; fidelidad = fuente de netstack-smoltcp 0.2.3 + RFC 9293 +
//! contrato de [`crate::tunnel::proxy::splice`]).
//!
//! ## El problema que resuelve (REQUISITO load-bearing surgido de la review de M1)
//! El `poll_shutdown` del `TcpStream` de netstack-smoltcp 0.2.3 NO se comporta como el de un socket
//! del SO: solo devuelve `Ready` cuando el cierre es COMPLETO (smoltcp `State::Closed`), no justo tras
//! emitir el FIN. Verificado en fuente (`netstack-smoltcp-0.2.3/src/tcp.rs:560-581`): la primera
//! llamada pone `send_state = Close` (SHUT_WR) y devuelve `Poll::Pending`; solo retorna `Ready` cuando
//! el Runner ve `send_state == Closed`, que fija únicamente al alcanzar `State::Closed` (`tcp.rs:221`).
//!
//! Cuando [`splice`](crate::tunnel::proxy::splice) (T1) cablea su `sock_w.shutdown()` contra ese
//! `TcpStream` (en la dirección overlay→socket), eso produce dos patologías:
//!  - **Caso común** (el overlay cierra primero, p. ej. HTTP `Connection: close`): el `shutdown()`
//!    BLOQUEA ~10 s (TIME_WAIT/`CLOSE_DELAY` de smoltcp) antes del `join!` y el `zw.close()`. Un socket
//!    del SO retornaría al instante.
//!  - **CUELGUE NO ACOTADO + leak**: si el overlay cae a mitad de sesión (`zr` EOF + error de escritura
//!    en `zw`) y la app local sigue viva (ACKea keepalives) sin mandar nunca su FIN, el lado socket queda
//!    en FinWait2 PARA SIEMPRE → `State::Closed` jamás llega → `poll_shutdown` queda `Pending` → el
//!    `join!` de `splice` se cuelga y se filtran el conn-id ziti y la task. Un socket del SO no colgaría.
//!
//! ## La solución (enfoque aditivo, `splice` INTACTO)
//! [`InterceptTcpStream`] envuelve el `TcpStream` de netstack y delega `poll_read`/`poll_write`/
//! `poll_flush` tal cual, pero su [`poll_shutdown`](InterceptTcpStream::poll_shutdown) **sondea el inner
//! UNA vez** (lo justo para fijar `send_state = Close` → el Runner emite el FIN real) y devuelve `Ready`
//! INMEDIATAMENTE, sin esperar a `State::Closed`. Así el `splice` EXISTENTE (sin modificar) lo splicea
//! como cualquier `S: AsyncRead + AsyncWrite + Unpin` y nunca se cuelga en el half-close. Es exactamente
//! la semántica de `shutdown(SHUT_WR)` de un socket del SO: retorna en cuanto el FIN está encolado.
//!
//! ### Por qué NO se pierden datos (la superficie de `fidelity_risk`, verificada en fuente)
//! El Runner de netstack emite el FIN (`socket.close()`) SOLO cuando `send_state == Close` Y el
//! `send_buffer` está VACÍO (`tcp.rs:242-249`), drenándolo antes (`tcp.rs:306-329`). Y `splice` llama a
//! `shutdown()` SOLO tras haber `write_all`-eado cada byte al `send_buffer` (vía `poll_write`). Por tanto
//! devolver `Ready` antes de tiempo no puede truncar: el FIN sigue saliendo DESPUÉS de drenar todo lo
//! escrito (la propiedad "drain-before-FIN" que el test `data_written_before_shutdown_is_flushed_before_fin`
//! de M1 fija en la pila cruda, intacta aquí porque NO tocamos la lógica del Runner).
//!
//! ### Por qué el FIN está GARANTIZADO incluso tras soltar el stream
//! Quien emite el FIN en segundo plano es la **task Runner** de netstack, no el stream: mientras el
//! Runner viva drena el `send_buffer` y emite el FIN (`socket.close()`) aunque este `TcpStream` ya se
//! haya soltado. Que el `control` sea un `Arc<SpinMutex<…>>` co-poseído por el `TcpStream` y el mapa
//! `sockets` del Runner (`tcp.rs:156-175`) es NECESARIO —sobrevive al `Drop` del stream— pero NO
//! suficiente: el Arc no sirve de nada si nadie lo sondea; el garante real es la liveness del Runner
//! (vivo mientras viva el device). Sondear el inner una vez deja `send_state` ≥ `Close` en TODOS los
//! casos; aunque no lo hiciéramos, el `Drop` del `TcpStream` también pone `Close` (`tcp.rs:467`) como
//! backstop. Sondeamos a propósito para emitir el FIN EN EL momento del half-close (fiel al GATE de M1
//! y a un socket del SO), no diferido al Drop. La ÚNICA vía de pérdida del FIN es el teardown del stack
//! ENTERO (`InterceptStack::Drop` aborta el Runner): ahí device + egress también se van, así que el FIN
//! es indistribuible de todos modos → competencia del orquestador (cuándo soltar la pila), DIFERIDO a
//! M2b, misma clase que la desviación LocalSet-drop documentada en `proxy.rs`.
//!
//! ### Residual consciente (honesto, NO "sin leak")
//! El fix elimina el cuelgue del `join!` y la fuga de la **task** de `splice` (la task retorna y suelta
//! sus clones `Arc<ChannelState>` `zr`/`zw`, que antes quedaban pineados para siempre). Matiz sobre el
//! conn-id ziti del mux: M2a NO lo libera. `zw.close()` (`edge::data::EdgeWriteHalf::close`) escribe el
//! `StateClosed` y solo TRAS un write con éxito hace `conns.remove(&conn_id)`; si el overlay está MUERTO
//! ese write falla (`?` retorna antes) y el conn-id lo reclama el teardown ORTOGONAL del canal
//! (`mark_closed` → `conns.clear()` en muerte de la rx-loop / `Drop` / sonda de latencia), NO este fix.
//! (Por eso el test del half-open NO asierta `conn_count == 0`.)
//!
//! Aparte, el socket smoltcp subyacente PUEDE quedar en FinWait2 hasta que netstack lo recicle vía su
//! keepalive (28 s) / timeout (`tcp.rs:143-145`); netstack solo lo retira del mapa al llegar a
//! `State::Closed` (`tcp.rs:221`) y no expone un abort público. Es un recurso interno de netstack (un
//! socket + sus buffers), acotado por su propia maquinaria, NO una task nuestra colgada. Un abort duro
//! requeriría vendorizar netstack → DIFERIDO a M3/vendor (el seam donde el DNS ya obliga a vendorizar).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use netstack_smoltcp::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// El `TcpStream` interceptado que la pila ([`super::stack::InterceptStack`]) entrega para splicear
/// contra el overlay, con half-close ACOTADO en `poll_shutdown` (ver el docstring del módulo).
///
/// Delega lectura/escritura/flush al `TcpStream` de netstack sin cambios; solo `poll_shutdown` desvía
/// del comportamiento de netstack (que esperaría a `State::Closed`) para retornar en cuanto el FIN
/// queda disparado, igual que `shutdown(SHUT_WR)` de un socket del SO. `Unpin` (el inner lo es).
pub struct InterceptTcpStream {
    inner: TcpStream,
}

impl InterceptTcpStream {
    /// Envuelve el `TcpStream` crudo de netstack-smoltcp con el half-close acotado.
    pub(crate) fn new(inner: TcpStream) -> Self {
        Self { inner }
    }
}

impl AsyncRead for InterceptTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for InterceptTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    /// Half-close ACOTADO. Sondea el `poll_shutdown` del inner UNA vez —lo justo para fijar
    /// `send_state = Close` y que el Runner de netstack drene el `send_buffer` y emita el FIN real— y
    /// devuelve `Ready` SIN esperar a `State::Closed` (que tardaría ~10 s en TIME_WAIT o jamás llegaría
    /// con un peer half-open en FinWait2). El Runner, que co-posee el `control` Arc del socket, completa
    /// el cierre en segundo plano aunque este stream se suelte después. Espejo de `shutdown(SHUT_WR)`
    /// de un socket del SO. Ver el docstring del módulo para la prueba de no-pérdida de datos y la
    /// garantía del FIN.
    ///
    /// DESVIACIÓN CONSCIENTE del contrato literal de `AsyncWrite::poll_shutdown` de tokio ("`Ready`
    /// ⟹ datos vaciados"): devolvemos `Ready` con bytes aún en el `send_buffer` (netstack los vacía
    /// luego, asíncrono). Deliberado y benigno: `splice` no lee/escribe `sock_w` tras el `shutdown`, y
    /// un "flush-before-Ready" estricto es IMPOSIBLE en netstack (`poll_flush` es un no-op,
    /// `tcp.rs:556-558`) sin bloquear hasta `State::Closed` — justo el cuelgue que M2a elimina.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_shutdown(cx) {
            // El inner ya está en cierre COMPLETO (`State::Closed`): propaga su resultado terminal.
            Poll::Ready(res) => Poll::Ready(res),
            // El sondeo dejó `send_state` ≥ `Close` → el FIN está disparado; no bloqueamos esperando
            // `State::Closed`. Esta es la desviación CONSCIENTE respecto a netstack que acota el cierre.
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}
