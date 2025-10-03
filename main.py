import tkinter as tk
import json
from time import sleep
from sys import executable
from pathlib import Path
from binascii import hexlify, unhexlify
from random import choice, choices, shuffle, randint
from subprocess import Popen, check_call
from os import getcwd
from string import ascii_lowercase, ascii_uppercase, digits
from base64 import b64decode, b64encode
from platform import system
from webbrowser import open as web_open

def install_package(package: str)->None:
   """
   Installs a package if its not present
   :Params Package:  the package to install
   :return: None
   """

   print(f"Package Missing,\nInstalling Package: {package}")

   for i in range(0, randint(3,7)): # animation
      
      for ii in range(0, 3):

         print('.' * 1, end="", flush=True)
         sleep(0.1)

      sleep(0.3)
      print()

   check_call([executable, "-m", "pip", "install", package])

try: # safe import for external packages
   import customtkinter as ctk

except:
   install_package("customtkinter")
   import customtkinter as ctk

try: # safe import for external packages
   from pyperclip import copy

except:
   install_package("pyperclip")
   from pyperclip import copy

try: # safe import for external packages

   from Crypto.Cipher import AES
   from Crypto.Util.Padding import pad, unpad
   from Crypto.Random import get_random_bytes

except ImportError:

   install_package("pycryptodome")

   from Crypto.Cipher import AES
   from Crypto.Util.Padding import pad, unpad
   from Crypto.Random import get_random_bytes

def encrypt(key: bytes, password: str) -> bytes:
   """
   takes the password and key and aes encrypts the password and returns an encrypted string
   :param key:
   :param password:
   :return: encrypted string
   """

   # Convert password to bytes
   bytes_password: bytes = password.encode('utf-8')

   # Generate random IV
   iv = get_random_bytes(AES.block_size)
   cipher = AES.new(key, AES.MODE_CBC, iv)
   ciphertext = cipher.encrypt(pad(bytes_password, AES.block_size))

   # Return iv + ciphertext so iv can be extracted during decryption
   return iv + ciphertext

def decrypt(key: bytes) -> str:
   """
   Decrypt all entries in data.json using the provided key.
   :param key: AES key (in bytes)
   :return: A formatted string of all decrypted entries
   """

   try:
      with open("data.json", "r") as file:
         encrypted_data = json.load(file)

   except (FileNotFoundError, json.JSONDecodeError):
      return "No data found or file is corrupted."

   output = []

   for site, credentials in encrypted_data.items():
      
      try:
         # Decode base64 strings back to bytes
         username_encrypted = b64decode(credentials['username'])
         password_encrypted = b64decode(credentials['password'])

         # Extract IV and ciphertext
         iv_user = username_encrypted[:AES.block_size]
         ct_user = username_encrypted[AES.block_size:]

         iv_pass = password_encrypted[:AES.block_size]
         ct_pass = password_encrypted[AES.block_size:]

         # Decrypt username and password
         cipher_user = AES.new(key, AES.MODE_CBC, iv_user)
         username = unpad(cipher_user.decrypt(ct_user), AES.block_size).decode('utf-8')

         cipher_pass = AES.new(key, AES.MODE_CBC, iv_pass)
         password = unpad(cipher_pass.decrypt(ct_pass), AES.block_size).decode('utf-8')

         output.append(f"Site: {site}\n  Username: {username}\n  Password: {password}\n")

      except Exception as e:
         output.append(f"Site: {site}\n  Error decrypting: {str(e)}\n")

   return "\n".join(output)

def generate_password() -> str:
   """
   generates a string password made of upper and lowercase characters
   :return: string password 21 characters long
   """

   lowercase: str = ascii_lowercase
   uppercase: str = ascii_uppercase
   digit: str = digits
   symbols: str = "~`!@#$%^&()-_+={[}]|:;'<>,./?*"

   all_chars: str = lowercase + uppercase + digit + symbols
   password: list[str] = [
      choice(lowercase),
      choice(uppercase),
      choice(digit),
      choice(symbols),
   ]

   password += choices(all_chars, k=21 - len(password))
   shuffle(password)

   return ''.join(password)

def frame_maker(data:str)->list[int]:
   """
   takes an input in the form of 'width,x,height' and breaks it down in to int's
   where it is divided into a value so it looks good on a screen
   :param data: Str
   :return: width and height of frame
   """

   width, height = data.split('x')
   return [
      int(float(width) / 16) - 11,
      int(float(height) / 9) - 5
   ]

def make_key() -> str:
   """
   generates a new key for encryption and decryption
   :return: key in hex format
   """

   byte_key = get_random_bytes(16)
   hex_key = hexlify(byte_key).decode('ascii')  # decode bytes to str
   return hex_key

def decrypt_key(hex_key:str) -> bytes | None:
   """
   takes the key in hex format and returns it in byte form
   :param hex_key: str
   :return: key in byte form if possible
   """
   
   try:
      return unhexlify(hex_key)
   
   except Exception:
      return None

def password_maker(username:str, key:str,password:str,site:str)->None:
   """
   takes the unencrypted password, key in plaintext form, and site and turns them in to a json entry
   :param username:
   :param key:
   :param password:
   :param site:
   :return: None
   """

   encrypted_username_bytes = encrypt(decrypt_key(key),username)
   encrypted_username_b64 = b64encode(encrypted_username_bytes).decode('utf-8')

   encrypted_password_bytes = encrypt(decrypt_key(key), password)
   encrypted_password_b64 = b64encode(encrypted_password_bytes).decode('utf-8')

   try:

      with open('data.json', 'r') as file:

         data = json.load(file)

         if not isinstance(data, dict):

            data = {}

   except (FileNotFoundError, json.JSONDecodeError):
      data = {}

   data[site] = {
      "username": encrypted_username_b64,
      "password": encrypted_password_b64
   }

   with open('data.json', 'w') as file:
      json.dump(data, file, indent=4)

def get_screen_size() -> str:
   """
   gets the current resolution in 1080p format
   :return: screensize
   """

   root = tk.Tk()
   root.withdraw()
   width = root.winfo_screenwidth()
   height = root.winfo_screenheight()

   return f"{width}x{height}"

def set_geometry(width:int,height:int)->str:
   """
   Uses the width and height of the frames to get the size of the window
   :param width: width of frame
   :param height: height of frame
   :return: width and height of window
   """

   width = width * 16
   height = height * 9
   return f"{width}x{height}"

class App(ctk.CTk):
   """
   :var title: name of the application
   :var frame_height: height of the frames
   :var frame_width: width of the frames
   :var tile_colour: colour of the background tile
   :var button height: height of the buttons
   :var button width: width of the buttons
   :var button radius: radius of the buttons
   :var frames: list of frames
   :var button_text: colour of the button text
   :var hover_colour: colour of the button when you hover over it
   :var button_colour: colour of the button
   """

   def __init__(self):
      super(App, self).__init__()

      size: str = get_screen_size()
      valid_sizes = ["1280x720", "1920x1080", "3840x2160", "7680x4320"]

      if size not in valid_sizes:

         size = '1920x1080'

      self.title("Python Password Manager")
      self.resizable(width=False, height=False)
      self._set_appearance_mode("dark")
      self.button_height:int = 50
      self.button_width:int = 200
      self.button_radius:int = 15
      self.button_colour: str = "#32CD32"
      self.hover_colour:str = "#06402B"
      self.button_text:str = "#000000"
      self.frame_height, self.frame_width = frame_maker(size)
      self.tile_colour: str = "#353935"
      self.configure(fg_color=self.tile_colour)
      self.geometry(set_geometry(self.frame_width,self.frame_height))
      self.frames = []

      for col in range(16):

         column_frames = []

         for row in range(9):

            if col > 1:

               frame = ctk.CTkFrame(
                  self,
                  fg_color=self.tile_colour,
                  width=self.frame_width,
                  height=self.frame_height,
                  corner_radius = 0
               ).grid(row=row, column=col, sticky="nsew")

            else:
               frame = ctk.CTkFrame(
                  self,
                  fg_color="#28282B",
                  width=self.frame_width,
                  height=self.frame_height,
                  corner_radius=0
               ).grid(
                  row=row,
                  column=col,
                  sticky="nsew",
                  rowspan=2
               )

            column_frames.append(frame)
         self.frames.append(column_frames)

      self.draw()

      #self.test()

      self.protocol("WM_DELETE_WINDOW", self.on_closing)

   def on_closing(self) -> None:
      """
      stops an error message from displaying when the winndow is closed
      :return: None
      """

      try:
         self.quit() 

      except:
         pass
      
      try:
         self.destroy()

      except: 
         pass

   def test(self) -> None:
      """
      tests ui, places a coord in every frame, and colours in every frame with a unique colour to make them easy to count
      :return: None
      """

      for col in range(0, 16):

         for row in range(0, 9):

            ctk.CTkLabel(
               self,
               text_color="#ffffff",
               text=f"{col},{row}"
            ).grid(
               row=row,
               column=col
            )

            """
            rand_color = lambda: random.randint(0, 255)
            hex_color: str = f"#{rand_color():02X}{rand_color():02X}{rand_color():02X}"
            self.frame = ctk.CTkFrame(self,width=self.frame_width,height=self.frame_height, fg_color=hex_color).grid(row=row, column=col)
            """

   def make_key(self) -> None:
      """
      draws the ui for getting a new master key, and draws the button used for copying the text to the clipboard
      :return: None
      """

      self.hide_ui()

      key = make_key()

      text = ctk.CTkTextbox(
         self,
         width=200,
         height=70,
         fg_color=self.tile_colour,
         text_color="#ffffff",
      )
      text.grid(
         row=1,
         column=2,
         columnspan=2
      )
      text.insert(
         "0.0",
         f"New master key:\n{key}"
      )
      text.configure(state="disabled")

      ctk.CTkButton(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         text="Copy to clipboard",
         command=lambda:self.coppy_to_clipboard(key),
         fg_color=self.button_colour,
         hover_color = self.hover_colour,
         text_color=self.button_text,
      ).grid(
         row = 2,
         column = 2,
         columnspan = 2
      )

   def decrypt_handler(self) -> None:
      """
      starts the process of decrypting the stored data
      :return: None
      """

      key:str = ""

      key = self.Decryption_key.get()

      textbox = ctk.CTkTextbox(
         self,
         width=500,
         height=700,
         corner_radius= 45
      )
      textbox.grid(
         row = 1,
         column = 8,
         rowspan = 7,
         columnspan =4
      )
      try:
         textbox.insert("0.0", f"{decrypt(decrypt_key(key))}")

      except TypeError:
         textbox.insert("0.0", "Enter A Valid Key To Decrypt")

   def new_password(self) -> None:

      self.hide_ui()

      password = generate_password()

      text = ctk.CTkTextbox(
         self,
         width=200,
         height=70,
         fg_color=self.tile_colour,
         text_color="#ffffff",
      )
      text.grid(
         row=1,
         column=2,
         columnspan=2
      )
      text.insert(
         "0.0",
         f"New Password:\n{password}"
      )
      text.configure(state="disabled")

      ctk.CTkButton(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         text="Copy to clipboard",
         command=lambda: self.coppy_to_clipboard(password),
         fg_color=self.button_colour,
         hover_color=self.hover_colour,
         text_color=self.button_text,
      ).grid(
         row=2,
         column=2,
         columnspan=2
      )

   def add_password(self)->None:
      """
      draws the ui to add a new password
      :return: None
      """

      self.hide_ui()

      self.enty_username = ctk.CTkEntry(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         placeholder_text="Username"
      )
      self.enty_username.grid(
         row=0,
         column=2,
         columnspan=2
      )

      self.entry_new_password = ctk.CTkEntry(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         placeholder_text="Password"
      )
      self.entry_new_password.grid(
         row=1,
         column=2,
         columnspan=2
      )

      self.entry_site = ctk.CTkEntry(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         placeholder_text="Site"
      )
      self.entry_site.grid(
         row=2,
         column=2,
         columnspan=2
      )

      self.entry_key = ctk.CTkEntry(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         placeholder_text="Key / Master Key"
      )
      self.entry_key.grid(
         row=3,
         column=2,
         columnspan=2
      )

      ctk.CTkButton(
         self,
         width=self.button_width,
         height=self.button_height,
         corner_radius=self.button_radius,
         fg_color=self.button_colour,
         hover_color=self.hover_colour,
         text_color=self.button_text,
         text="Generate password",
         command=lambda: self.password_handler()
      ).grid(
         row=4,
         column=2,
         columnspan=2
      )

   def password_handler(self)->None:
      """
      takes the password, site, and key and puts it in the encryption method
      :return: None
      """

      username: str =self.enty_username.get()
      key: str = self.entry_key.get()
      password: str = self.entry_new_password.get()
      site: str = self.entry_site.get()

      if username != "" and key != "" and password != "" and site != "":

         password_maker(username, key, password, site)
         self.hide_ui()

   def coppy_to_clipboard(self, data: str) -> None:
      """
      copy text to clipboard
      :param data:
      :return: None
      """

      copy(data)
      self.hide_ui()

   def open_file_location(self) -> None:
      """
      Opens to the File location
      :return: None
      """

      self.hide_ui()

      if system() == "Windows":
         Popen(f"explorer {getcwd()}")

      elif system() == "Darwin":  # macOS
         Popen(["open", getcwd()])

      else:  # Linux
         Popen(["xdg-open", getcwd()])

   def help(self)->None:
      self.clear_panel()

      content:list[str] = [
         "Generate a master key, this is used to store and retrieve all your passwords",
         "This means if you loose the master key you loose access to everything",
         "Input your username, password, and the sites name alongside the key to store it",
         "Enter your key, then press the decrypt button to get back your stored passwords",
         "<------ Press the Home button, or the clear Gui button to go back to the decrypt screen",
         "Use the open file location button to find where your passwords are stored 'data.json'"
      ]

      text_col:str = "#ffffff"

      ctk.CTkLabel(
         self,
         text="Help Menu",
         text_color=text_col,
         font=('Arial',23),
         fg_color="#2e2e2e"
      ).grid(
         row = 1,
         column =7,
         columnspan =2
      )

      ctk.CTkLabel(
         self,
         text=content[0],
         text_color=text_col,
         font=('Arial', 17),
         fg_color="#2e2e2e"
      ).grid(
         row=2,
         column=4,
         columnspan=8
      )

      ctk.CTkLabel(
         self,
         text=content[1],
         text_color=text_col,
         font=('Arial', 17),
         fg_color="#2e2e2e"
      ).grid(
         row=3,
         column=4,
         columnspan=8
      )

      ctk.CTkLabel(
         self,
         text=content[2],
         text_color=text_col,
         font=('Arial', 17),
         fg_color="#2e2e2e"
      ).grid(
         row=4,
         column=4,
         columnspan=8
      )

      ctk.CTkLabel(
         self,
         text=content[3],
         text_color=text_col,
         font=('Arial', 17),
         fg_color="#2e2e2e"
      ).grid(
         row=5,
         column=4,
         columnspan=8
      )

      ctk.CTkLabel(
         self,
         text=content[4],
         text_color=text_col,
         font=('Arial', 17),
         fg_color="#2e2e2e"
      ).grid(
         row=6,
         column=4,
         columnspan=8
      )

      ctk.CTkLabel(
         self,
         text=content[5],
         text_color=text_col,
         font=('Arial', 17),
         fg_color="#2e2e2e"
      ).grid(
         row=7,
         column=4,
         columnspan=8
      )

   def draw(self)->None:
      """
      draws the ui
      :return: None
      """

      ctk.CTkLabel(
         self,
         text = "Python Password Manager",
         text_color="#ffffff",
         font=('Arial', 27)
      ).grid(
         row = 0,
         column = 7,
         columnspan = 2
      )

      def side_bar()->None:
         """
         draws the sidebar
         :return: None
         """

         frame_colour = "#28282B"

         for row in range(0, 9):
            
            ctk.CTkFrame(
               self,
               corner_radius=0,
               fg_color=frame_colour,
               height=self.frame_height,
               width=self.frame_width
            ).grid(
               row=row,
               column=0,
               sticky="nsew",
               columnspan=2
            )

      def buttons()->None:
         """
         draws the buttons for the sidebar
         :return: None
         """

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Generate Key",
            command=self.make_key,
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text
         ).grid(
            row=0,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Open File Location",
            command=lambda: self.open_file_location(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text
         ).grid(
            row=1,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Add new password",
            command=lambda: self.add_password(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row = 2,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Generate password",
            command=lambda: self.new_password(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row=3,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Clear GUI",
            command=lambda: self.reset_ui(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row=4,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Github :)",
            command=lambda: web_open("https://github.com/ifanjones-codebase"),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row=5,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Home",
            command=lambda: self.fill_panel(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row=6,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Help",
            command=lambda: self.help(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row=7,
            column=0,
            columnspan=2
         )

         ctk.CTkButton(
            self,
            width=self.button_width,
            height=self.button_height,
            corner_radius=self.button_radius,
            text="Exit",
            command=lambda: self.on_closing(),
            fg_color=self.button_colour,
            hover_color=self.hover_colour,
            text_color=self.button_text,
         ).grid(
            row=8,
            column=0,
            columnspan=2
         )


      side_bar()  # calls the draw sidebar
      buttons()  # draws the buttons
      self.fill_panel() # draws teh ui on the main panel

   def fill_panel(self) -> None:
      """
      draws the panel elements
      :return: None
      """

      self.clear_panel()

      ctk.CTkLabel(
         self,
         text="enter a valid key to decrypt",
         text_color="#ffffff",
         font=('Arial', 15),
         fg_color="#2e2e2e"
      ).grid(
         row=1,
         column=4,
         columnspan=3
      )

      ctk.CTkLabel(
         self,
         text="if you dont have one make one using the get key button",
         text_color="#ffffff",
         font=('Arial', 15),
         fg_color="#2e2e2e"
      ).grid(
         row=2,
         column=4,
         columnspan=3
      )

      self.Decryption_key = ctk.CTkEntry(
         self,
         width=self.button_width + 50,
         height=self.button_height,
         corner_radius=self.button_radius,
         placeholder_text="Key / Master Key for Decryption"
      )
      self.Decryption_key.grid(
         row=3,
         column=4,
         columnspan=3
      )

      ctk.CTkButton(
         self,
         width=self.button_width + 50,
         height=self.button_height,
         corner_radius=self.button_radius,
         text="Decrypt Passwords",
         command=lambda: self.decrypt_handler(),
         fg_color=self.button_colour,
         hover_color=self.hover_colour,
         text_color=self.button_text,
      ).grid(
         row=4,
         column=4,
         columnspan=3
      )

   def hide_ui(self)->None:
      """
      hides the no longer needed ui
      :return: None
      """

      for col in range(0, 9):

         for row in range(0, 16):

            if 1 < col < 4:

               ctk.CTkFrame(
                  self,
                  fg_color=self.tile_colour,
                  width=self.frame_width,
                  height=self.frame_height,
                  corner_radius=0
               ).grid(
                  row=row,
                  column=col,
                  sticky="nsew",
                  rowspan=2
               )

   def clear_panel(self) -> None:
      """
      draws the panel and main ui elements
      :return: None
      """

      panel_colour: str = "#2e2e2e"

      for row in range(0, 9):

         for col in range(0, 16):

            if 3 < col < 12:

               if 0 < row < 8:

                  ctk.CTkFrame(
                     self, corner_radius=0,
                     fg_color=panel_colour,
                     height=self.frame_height,
                     width=self.frame_width
                  ).grid(
                     row=row,
                     column=col,
                     sticky="nsew",
                     columnspan=2
                  )

   def reset_ui(self) -> None:
      """
      resets the entire screen
      :return: Non
      """

      self.fill_panel()
      self.hide_ui()

if __name__ == '__main__':

   file_path = Path("data.json")

   if not file_path.exists():
      
      # Create an empty JSON file
      with open(file_path, "w") as f:
         json.dump({}, f)


   app = App()
   app.mainloop()
