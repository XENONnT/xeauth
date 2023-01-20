"""Console script for xeauth."""
import os
import sys
import xeauth
import click
import httpx
import pathlib
from rich.console import Console
from rich.progress import track
from rich.live import Live
from rich.table import Table


@click.group()
def main():
    with click.get_current_context() as ctx:
        if ctx.invoked_subcommand is None:
            click.echo(ctx.get_help())


@main.group()
def secrets():
    with click.get_current_context() as ctx:
        if ctx.invoked_subcommand is None:
            click.echo(ctx.get_help())


@main.group()
def admin():
    with click.get_current_context() as ctx:
        if ctx.invoked_subcommand is None:
            click.echo(ctx.get_help())


@main.command()
def login():
    token = xeauth.cli_login()
    token.to_file(xeauth.config.TOKEN_FILE)
    click.echo(f"Token saved to: {xeauth.config.TOKEN_FILE}")


@secrets.command()
@click.option("--name", prompt="Name", help="Your full name.")
@click.option(
    "--email", prompt="Email", help="Your email address as it is registered on github."
)
@click.option("--passphrase", prompt="Passphrase", help="Your passphrase for the key.")
@click.option("--gnu-home", default=None, help="Your gnu home directory.")
def key_gen(name, email, passphrase, gnu_home):
    HELP_LINK = "https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account"
    key = xeauth.utils.new_gpg_key(name, email, passphrase, gnu_home)
    click.echo("Key generated:")
    click.echo(key)
    click.echo(f"Please see {HELP_LINK} for help adding the key to github.")


@admin.command()
@click.option("--filename", default=None)
def list_usernames(filename):
    console = Console()

    with console.status("Fetching active user list..."):
        usernames = xeauth.admin.get_active_usernames()

    if filename is not None:
        with console.status("Saving user list to file..."):
            with open(filename, "w") as f:
                for username in usernames:
                    f.write(f"{username}\n")
        click.echo(f"Active usernames written to file {filename}.")
    else:
        click.echo("Active usernames:")
        for username in usernames:
            click.echo(username)


@admin.command()
@click.option(
    "--token",
    prompt="Github token",
    default=xeauth.config.GITHUB_TOKEN,
    help="A valid github API token.",
)
@click.option("--path", 
            prompt="Destination folder", 
            default="~/xenon_user_keys",
            )
@click.option("--import_keys", is_flag=True,
            default=True,
            )
@click.option("--gnuhome", 
            prompt="GPG home path", 
            default="~/.gnupg",
            )
def fetch_keys(token, path, import_keys, gnuhome):
    if path:
        path = pathlib.Path(path)
        path = path.expanduser()

    console = Console()

    with console.status("Fetching active user list..."):
        usernames = xeauth.admin.get_active_usernames()

    table = Table()
    table.add_column("Username")
    table.add_column("Public Key")
    with Live(table, refresh_per_second=4, console=console):
        for username in track(usernames, description="Fetching keys..."):
            keys = xeauth.admin.get_user_keys(username, token=token)
            for key in keys:
                table.add_row(username, key["raw_key"])
                key["username"] = username

                folder = path / key["username"]
                if not folder.exists():
                    folder.mkdir(parents=True)
                filename = folder / key["key_id"]
                with open(filename, "w") as f:
                    f.write(key["raw_key"])
                if import_keys:
                    xeauth.admin.import_key(key['raw_key'], gnuhome=gnuhome)

    console.print(f"Valid keys written to folder {path.absolute()}.")


if __name__ == "__main__":
    main()  # pragma: no cover
