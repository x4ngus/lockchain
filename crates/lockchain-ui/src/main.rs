// UI Architecture modules
mod components;
mod dispatcher;
mod panels;
mod provider;
mod shell;

/// Launch the Control Deck application with the AppShell architecture.
pub fn main() -> iced::Result {
    shell::run()
}
