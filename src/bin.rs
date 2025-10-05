use interface_events::IfController;

fn main() {
    let ifc = IfController::new();
    let if_rx = ifc.subscribe();
    for _event in if_rx.iter() {
        println!("got if event");
    }
}
