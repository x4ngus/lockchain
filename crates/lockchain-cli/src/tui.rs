//! Terminal UI for interactively unlocking ZFS datasets.
//!
//! This interface currently supports the ZFS provider only.

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use lockchain_core::{
    error::LockchainError,
    provider::{DatasetKeyDescriptor, KeyState},
    service::{LockchainService, UnlockOptions},
    LockchainConfig, Zeroizing,
};
use lockchain_zfs::SystemZfsProvider;
use ratatui::{
    prelude::{Alignment, Constraint, Direction, Frame, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use rpassword::prompt_password;
use std::{
    io::{self, Stdout},
    sync::Arc,
    time::{Duration, Instant},
};

/// Launch the TUI with shared config/service references.
pub fn launch(
    config: Arc<LockchainConfig>,
    service: LockchainService<SystemZfsProvider>,
) -> Result<()> {
    let mut app = App::new(config, service);
    app.run()
}

/// Encapsulates TUI state, list data, and last operation outcome.
struct App {
    service: LockchainService<SystemZfsProvider>,
    datasets: Vec<DatasetKeyDescriptor>,
    selected: usize,
    last_error: Option<String>,
    status_message: Option<String>,
    status_timestamp: Instant,
    strict_usb: bool,
}

impl App {
    /// Hydrate the dataset list and stash service handles for later use.
    fn new(config: Arc<LockchainConfig>, service: LockchainService<SystemZfsProvider>) -> Self {
        let datasets = service.list_keys().unwrap_or_default();

        let _ = config; // config retained by caller; service owns needed state

        Self {
            service,
            datasets,
            selected: 0,
            last_error: None,
            status_message: None,
            status_timestamp: Instant::now(),
            strict_usb: false,
        }
    }

    /// Enter the alternate screen, start the event loop, and clean up on exit.
    fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = ratatui::backend::CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let res = self.event_loop(&mut terminal);

        disable_raw_mode()?;
        terminal.show_cursor()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;

        res
    }

    /// Render the UI and react to keyboard events until the user quits.
    fn event_loop(
        &mut self,
        terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    ) -> Result<()> {
        loop {
            terminal.draw(|f| self.render(f))?;

            if crossterm::event::poll(Duration::from_millis(200))? {
                match event::read()? {
                    Event::Key(key) => match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Up | KeyCode::Char('k') => {
                            if self.selected > 0 {
                                self.selected -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if self.selected + 1 < self.datasets.len() {
                                self.selected += 1;
                            }
                        }
                        KeyCode::Char('r') => {
                            self.refresh_status()?;
                        }
                        KeyCode::Char('s') => {
                            self.strict_usb = !self.strict_usb;
                            self.set_status(if self.strict_usb {
                                "Strict USB mode enabled"
                            } else {
                                "Strict USB mode disabled"
                            });
                        }
                        KeyCode::Char('p') => {
                            if let Err(err) = self.prompt_and_unlock() {
                                self.last_error = Some(err.to_string());
                            }
                        }
                        KeyCode::Enter => {
                            self.attempt_unlock()?;
                        }
                        KeyCode::Char('c') => {
                            self.last_error = None;
                        }
                        _ => {}
                    },
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }

            if self.status_message.is_some()
                && self.status_timestamp.elapsed() > Duration::from_secs(5)
            {
                self.status_message = None;
            }
        }
    }

    /// Reload keystatus from the service and keep selection stable.
    fn refresh_status(&mut self) -> Result<()> {
        self.datasets = self.service.list_keys()?;
        if !self.datasets.is_empty() {
            self.selected = self.selected.min(self.datasets.len() - 1);
        } else {
            self.selected = 0;
        }
        Ok(())
    }

    /// Kick off an unlock using the current selection and strict flag.
    fn attempt_unlock(&mut self) -> Result<()> {
        if self.datasets.is_empty() {
            self.last_error = Some("No datasets configured".into());
            return Ok(());
        }

        let dataset = self.datasets[self.selected].dataset.clone();
        let options = UnlockOptions {
            strict_usb: self.strict_usb,
            ..UnlockOptions::default()
        };

        match self.service.unlock_with_retry(&dataset, options) {
            Ok(report) => {
                if report.already_unlocked {
                    self.set_status("Dataset already unlocked");
                } else {
                    self.set_status("Unlock successful");
                }
                self.refresh_status()?;
            }
            Err(err) => match err {
                LockchainError::MissingKeySource(_) => {
                    self.last_error = Some(
                        "Key source missing. Insert USB or press 'p' to supply passphrase.".into(),
                    );
                }
                other => {
                    self.last_error = Some(other.to_string());
                }
            },
        }

        Ok(())
    }

    /// Temporarily drop raw mode, prompt for a passphrase, and retry the unlock.
    fn prompt_and_unlock(&mut self) -> Result<()> {
        if self.datasets.is_empty() {
            self.last_error = Some("No datasets configured".into());
            return Ok(());
        }

        disable_raw_mode()?;
        let dataset = self.datasets[self.selected].dataset.clone();
        let prompt = format!("Fallback passphrase for {}", dataset);
        let result = prompt_password(prompt);
        enable_raw_mode()?;

        let passphrase = match result {
            Ok(p) => p,
            Err(err) => {
                self.last_error = Some(format!("passphrase prompt failed: {err}"));
                return Ok(());
            }
        };

        let mut options = UnlockOptions {
            strict_usb: self.strict_usb,
            ..UnlockOptions::default()
        };
        options.fallback_passphrase = Some(Zeroizing::new(passphrase));

        match self.service.unlock_with_retry(&dataset, options) {
            Ok(report) => {
                if report.already_unlocked {
                    self.set_status("Dataset already unlocked");
                } else {
                    self.set_status("Unlock successful");
                }
                self.refresh_status()?;
            }
            Err(err) => {
                self.last_error = Some(err.to_string());
            }
        }

        Ok(())
    }

    /// Update the transient footer message and reset its timer.
    fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
        self.status_timestamp = Instant::now();
    }

    /// Draw the header, dataset list, and status footer in each frame.
    fn render(&self, f: &mut Frame<'_>) {
        let size = f.size();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Min(5),
                    Constraint::Length(3),
                ]
                .as_ref(),
            )
            .split(size);

        let header = Paragraph::new(vec![Line::from(vec![
            Span::styled(
                "LockChain :: TUI",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                "  q:quit  ↑/↓:select  enter:unlock  r:refresh  s:strictUSB  p:passphrase  c:clear",
            ),
        ])])
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, chunks[0]);

        let items: Vec<ListItem> = if self.datasets.is_empty() {
            vec![ListItem::new("No datasets configured")]
        } else {
            self.datasets
                .iter()
                .map(|entry| {
                    let status = match entry.state {
                        KeyState::Available => {
                            Span::styled("available", Style::default().fg(Color::Green))
                        }
                        KeyState::Unavailable => {
                            Span::styled("locked", Style::default().fg(Color::Red))
                        }
                        KeyState::Unknown(ref v) => {
                            Span::styled(v, Style::default().fg(Color::Yellow))
                        }
                    };
                    let line = vec![
                        Span::styled(&entry.dataset, Style::default().fg(Color::White)),
                        Span::raw("  →  "),
                        Span::styled(&entry.encryption_root, Style::default().fg(Color::Magenta)),
                        Span::raw("  ::  "),
                        status,
                    ];
                    ListItem::new(Line::from(line))
                })
                .collect()
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Datasets"))
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::Black))
            .highlight_symbol("▶ ");
        let mut state = ListState::default();
        state.select(if self.datasets.is_empty() {
            None
        } else {
            Some(self.selected)
        });
        f.render_stateful_widget(list, chunks[1], &mut state);

        let footer = if let Some(ref msg) = self.status_message {
            Paragraph::new(msg.as_str()).style(Style::default().fg(Color::Cyan))
        } else if let Some(ref err) = self.last_error {
            Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red))
        } else if self.strict_usb {
            Paragraph::new("Strict USB mode enabled").style(Style::default().fg(Color::Yellow))
        } else {
            Paragraph::new("Ready").style(Style::default().fg(Color::Green))
        };
        f.render_widget(
            footer.block(Block::default().borders(Borders::ALL)),
            chunks[2],
        );
    }
}
