# WhatsApp Sales Automation Bot

This application helps sales professionals automate the creation of WhatsApp groups and manage basic communication with contacts.

---

## ⚠️ IMPORTANT: WhatsApp's Terms of Service

Using automated systems on WhatsApp's platform is against their [Terms of Service](https://www.whatsapp.com/legal/terms-of-service). While this script includes features to minimize the risk of being banned (like human-like delays and one-time group creation), the risk can never be fully eliminated.

**To use this tool safely, you MUST follow these rules:**

1.  **GET CONSENT**: You must have explicit permission from every single contact before you add them to a group. Adding people without their consent is the fastest way to get your account banned.
2.  **DO NOT SPAM**: Do not use this tool for bulk messaging or spam. It is intended for creating small, specific groups for known contacts.
3.  **USE AT YOUR OWN RISK**: The creators of this tool are not responsible for any account bans or other consequences of its use.

---

## How to Use

1.  **Install Node.js**: If you don't have it, download and install the LTS version of [Node.js](https://nodejs.org/).
2.  **Install Dependencies**: Open a terminal or command prompt in the project folder and run the command: `npm install`
3.  **Configure Contacts**: Open the `contacts.json` file and add the contacts you want to include in the group. Make sure you have their permission!
    ```json
    [
        { "name": "First Contact", "role": "Sales", "phone": "91..." },
        { "name": "Second Contact", "role": "Sales", "phone": "91..." }
    ]
    ```
4.  **Configure the Bot**: Open `config.js` to set the group name and other options.
5.  **Run the Bot**: In your terminal, run the command: `node index.js`
6.  **Scan the QR Code**: The first time you run the bot, a QR code will appear in the terminal. Open WhatsApp on your phone, go to `Settings > Linked Devices > Link a Device`, and scan the code.

## How it Works

-   **Automatic Group Creation**: On the first run, the bot will automatically create the group defined in `config.js` with the contacts from `contacts.json`.
-   **State Management**: The bot creates a `state.json` file to remember that the group has been created. It will **not** try to create the group again on future runs.
-   **Opt-Out**: If a user replies with the word `STOP`, they will be permanently added to an opt-out list (stored in `state.json`) and will not receive further automated messages.
