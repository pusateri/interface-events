use interface_events::IfController;

fn main() {
    pretty_env_logger::init();

    match IfController::new() {
        Ok(ifc) => {
            let if_rx = ifc.subscribe();
            for event in if_rx.iter() {
                println!("event {event:?}");
            }
        }
        Err(e) => eprintln!("error initializing: {e}"),
    }
}
