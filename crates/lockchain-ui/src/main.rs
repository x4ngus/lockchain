// UI Architecture modules
mod panels;
mod provider;
mod dispatcher;
mod components;
mod shell;

/// Launch the Control Deck application with the AppShell architecture.
pub fn main() -> iced::Result {
    shell::run()
}
