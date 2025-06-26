import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import copy

class HexEditor:
    def __init__(self, root):
        """Initialize the Hex Editor GUI and its core variables."""
        self.root = root  # Main Tkinter window
        self.root.title("RZ Editor")  # Set window title
        self.sector_size = 512  # Size of each sector in bytes
        self.current_sector = 0  # Current sector being viewed
        self.filename = None  # Path to the loaded file
        self.file_data = b""  # holds the Binary data of the loaded file
        # Undo/Redo stacks to store previous and future states of file_data
        self.undo_stack = []
        self.redo_stack = []
        
        # Main frame to hold all widgets
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Scrollbar for the text area
        self.scrollbar = tk.Scrollbar(self.main_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill="y")
        # Text area to display hex and ASCII data
        self.text_area = tk.Text(self.main_frame, height=20, width=80, font=("Courier", 10),
                                yscrollcommand=self.scrollbar.set)
        self.text_area.pack(fill="both", expand=True)
        self.scrollbar.config(command=self.text_area.yview)
        self.text_area.bind("<Double-1>", self.edit_byte)  # Bind double-click to edit byte
        
        # Navigation frame for sector controls
        self.nav_frame = tk.Frame(self.main_frame)
        self.nav_frame.pack(fill="x", pady=5)
        
        tk.Label(self.nav_frame, text="Sector:").pack(side=tk.LEFT)
        self.sector_entry = tk.Entry(self.nav_frame, width=10)  # Entry for sector number
        self.sector_entry.pack(side=tk.LEFT, padx=5)
        self.sector_entry.insert(0, "0")
        
        tk.Button(self.nav_frame, text="Go", command=self.goto_sector).pack(side=tk.LEFT)
        tk.Button(self.nav_frame, text="Previous", command=lambda: self.goto_sector(self.current_sector - 1)).pack(side=tk.LEFT, padx=5)
        tk.Button(self.nav_frame, text="Next", command=lambda: self.goto_sector(self.current_sector + 1)).pack(side=tk.LEFT)
        
        # Search frame for search controls
        self.search_frame = tk.Frame(self.main_frame)
        self.search_frame.pack(fill="x", pady=5)
        
        tk.Label(self.search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = tk.Entry(self.search_frame, width=20)  # Entry for search query
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        self.search_mode = tk.StringVar(value="text")  # Variable to track search mode (text/hex)
        tk.Radiobutton(self.search_frame, text="Text", variable=self.search_mode, value="text").pack(side=tk.LEFT)
        tk.Radiobutton(self.search_frame, text="Hex", variable=self.search_mode, value="hex").pack(side=tk.LEFT, padx=5)
        
        self.case_sensitive = tk.BooleanVar(value=True)  # Toggle for case-sensitive search
        tk.Checkbutton(self.search_frame, text="Case Sensitive", variable=self.case_sensitive).pack(side=tk.LEFT, padx=5)
        
        tk.Button(self.search_frame, text="Search", command=self.search_sequence).pack(side=tk.LEFT)
        
        # Menu bar setup
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save", command=self.save_file)
        self.file_menu.add_command(label="Save As", command=self.save_file_as)
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Edit menu for undo/redo
        self.edit_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Edit", menu=self.edit_menu)
        self.edit_menu.add_command(label="Undo", command=self.undo, accelerator="Ctrl+Z")
        self.edit_menu.add_command(label="Redo", command=self.redo, accelerator="Ctrl+Y")
        
        # Bind keyboard shortcuts for undo/redo
        self.root.bind("<Control-z>", lambda event: self.undo())
        self.root.bind("<Control-y>", lambda event: self.redo())

    def open_file(self):
        """Open a file and load its binary data into the editor."""
        self.filename = filedialog.askopenfilename()  # Prompt user to select a file
        if self.filename:
            try:
                with open(self.filename, 'rb') as f:
                    self.file_data = f.read()  # Read file as binary
                self.current_sector = 0
                self.sector_entry.delete(0, tk.END)
                self.sector_entry.insert(0, "0")
                self.undo_stack.clear()  # Reset undo history
                self.redo_stack.clear()  # Reset redo history
                messagebox.showinfo("File", f"Opened: {self.filename}")
                self.display_sector(show_all=True)  # Show entire file
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {e}")

    def display_sector(self, show_all=False):
        """Display the current sector or entire file in the text area."""
        self.text_area.delete(1.0, tk.END)  # Clear text area
        if not self.file_data:
            self.text_area.insert(tk.END, "No data loaded yet.")
            return
        
        # Determine range to display
        if show_all:
            start = 0
            end = len(self.file_data)
        else:
            start = self.current_sector * self.sector_size
            end = min(start + self.sector_size, len(self.file_data))
        display_data = self.file_data[start:end]
        
        # Iterate over sectors in the range
        for sector in range(start // self.sector_size, (end + self.sector_size - 1) // self.sector_size): 
            sector_start = sector * self.sector_size
            sector_end = min(sector_start + self.sector_size, len(self.file_data))
            sector_data = self.file_data[sector_start:sector_end]
            
            self.text_area.insert(tk.END, f"\n--- Sector {sector} (Offset {sector_start:08x}) ---\n")
            
            # Display 16-byte chunks with hex and ASCII
            for i in range(0, len(sector_data), 16):
                chunk = sector_data[i:i+16]
                offset = sector_start + i
                hex_str = ' '.join(f'{b:02x}' for b in chunk)  # Hex representation
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)  # ASCII representation
                hex_padding = ' ' * (47 - len(hex_str))  # Padding for alignment
                line = f'{offset:08x}  {hex_str}{hex_padding} |{ascii_str}|\n'
                self.text_area.insert(tk.END, line)

    def goto_sector(self, sector=None):
        """Navigate to a specific sector by number."""
        if sector is None:
            try:
                sector = int(self.sector_entry.get())  # Get sector from entry
            except ValueError:
                messagebox.showerror("Error", "Invalid sector number")
                return
        
        max_sector = (len(self.file_data) - 1) // self.sector_size  # Calculate max sector
        if 0 <= sector <= max_sector:
            self.current_sector = sector
            self.sector_entry.delete(0, tk.END)
            self.sector_entry.insert(0, str(sector))
            self.display_sector(show_all=True)  # Refresh display
            sector_line = (self.current_sector * (self.sector_size // 16 + 2)) + 1  # Calculate line to scroll to
            self.text_area.see(f"{sector_line}.0")
        else:
            messagebox.showerror("Error", f"Sector must be between 0 and {max_sector}")

    def edit_byte(self, event):
        """Edit a byte at the double-clicked position."""
        index = self.text_area.index(tk.CURRENT)  # Get cursor position
        line, col = map(int, index.split('.'))
        
        line_text = self.text_area.get(f"{line}.0", f"{line}.end")
        if not line_text.strip() or line_text.startswith("---"):  # Skip empty or header lines
            return
        
        offset_str = line_text[:8]  # Extract offset from line
        hex_part = line_text[10:57].split()  # Extract hex values
        
        col -= 10  # Adjust column for hex section
        byte_pos = col // 3  # Calculate byte position in line
        if byte_pos < 0 or byte_pos >= len(hex_part):
            return
        
        file_offset = int(offset_str, 16) + byte_pos  # Calculate absolute file offset
        
        new_value = tk.simpledialog.askstring("Edit Byte", f"Enter new hex value (00-FF) at offset {file_offset:08x}:",
                                            initialvalue=hex_part[byte_pos])
        if new_value:
            try:
                new_byte = int(new_value, 16)
                if 0 <= new_byte <= 255:
                    # Save state for undo
                    self.undo_stack.append(copy.deepcopy(self.file_data))
                    self.redo_stack.clear()  # Clear redo on new edit
                    
                    data_list = bytearray(self.file_data)
                    data_list[file_offset] = new_byte  # Update byte
                    self.file_data = bytes(data_list)
                    self.display_sector(show_all=True)  # Refresh display
                    sector_line = (self.current_sector * (self.sector_size // 16 + 2)) + 1
                    self.text_area.see(f"{sector_line}.0")
                else:
                    messagebox.showerror("Error", "Value must be between 00 and FF")
            except ValueError:
                messagebox.showerror("Error", "Invalid hex value")

    def undo(self):
        """Revert to the previous file state."""
        if not self.undo_stack:
            messagebox.showinfo("Undo", "Nothing to undo")
            return
        # Save current state for redo
        self.redo_stack.append(copy.deepcopy(self.file_data))
        self.file_data = self.undo_stack.pop()  # Restore previous state
        self.display_sector(show_all=True)  # Refresh display
        sector_line = (self.current_sector * (self.sector_size // 16 + 2)) + 1
        self.text_area.see(f"{sector_line}.0")

    def redo(self):
        """Reapply the next file state."""
        if not self.redo_stack:
            messagebox.showinfo("Redo", "Nothing to redo")
            return
        # Save current state for undo
        self.undo_stack.append(copy.deepcopy(self.file_data))
        self.file_data = self.redo_stack.pop()  # Restore next state
        self.display_sector(show_all=True)  # Refresh display
        sector_line = (self.current_sector * (self.sector_size // 16 + 2)) + 1
        self.text_area.see(f"{sector_line}.0")

    def search_sequence(self):
        """Search for a text or hex sequence in the file."""
        query = self.search_entry.get().strip()
        if not query:
            messagebox.showerror("Error", "Enter a search term")
            return
        
        mode = self.search_mode.get()
        case_sensitive = self.case_sensitive.get()
        matches = []
        
        try:
            if mode == "hex":
                hex_values = query.replace("0x", "").replace(" ", "")
                if len(hex_values) % 2 != 0:
                    raise ValueError("Hex string must have an even number of characters")
                search_bytes = bytes.fromhex(hex_values)
                search_data = self.file_data
            else:  # mode == "text"
                search_bytes = query.encode("utf-8")
                if not case_sensitive:
                    search_data = self.file_data.lower()
                    search_bytes = search_bytes.lower()
                else:
                    search_data = self.file_data
            
            # Find all occurrences of the search bytes
            pos = -1
            while True:
                pos = search_data.find(search_bytes, pos + 1)
                if pos == -1:
                    break
                if mode == "text" and not case_sensitive:
                    if pos + len(search_bytes) <= len(self.file_data):
                        actual_bytes = self.file_data[pos:pos + len(search_bytes)]
                        if actual_bytes.lower() != search_bytes:
                            continue
                matches.append(pos)
            
            if not matches:
                messagebox.showinfo("Search", "No matches found")
                return
            
            self.show_search_results(matches, search_bytes)
        
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid {mode} input: {e}")

    def show_search_results(self, matches, search_bytes):
        """Display search results in a new window."""
        results_window = tk.Toplevel(self.root)
        results_window.title("Search Results")
        results_window.geometry("400x300")
        
        tk.Label(results_window, text=f"Found {len(matches)} matches").pack(pady=5)
        
        scrollbar = tk.Scrollbar(results_window)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        listbox = tk.Listbox(results_window, yscrollcommand=scrollbar.set, height=15)
        listbox.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=listbox.yview)
        
        # Populate listbox with match offsets
        for pos in matches:
            sector = pos // self.sector_size
            listbox.insert(tk.END, f"Offset {pos:08x} (Sector {sector})")
        
        def goto_match(event=None):
            """Navigate to the selected match."""
            selection = listbox.curselection()
            if not selection:
                return
            match_idx = selection[0]  # 0 is the row number in the listbox
            match_pos = matches[match_idx] 
            
            self.current_sector = match_pos // self.sector_size 
            self.sector_entry.delete(0, tk.END) 
            self.sector_entry.insert(0, str(self.current_sector)) 
            self.display_sector(show_all=True) 
            
            offset_in_sector = match_pos % self.sector_size 
            line_in_sector = offset_in_sector // 16 
            col_in_line = (offset_in_sector % 16) * 3 + 10 
            
            total_lines_before = (self.current_sector * (self.sector_size // 16 + 2)) + line_in_sector + 3 
            self.text_area.see(f"{total_lines_before}.0") 
            
            # Highlight the match
            start_idx = f"{total_lines_before}.{col_in_line}"  # Calculate start index for highlight
            hex_str = ' '.join(f'{b:02x}' for b in search_bytes)  # Hex representation of search bytes
            end_idx = f"{total_lines_before}.{col_in_line + len(hex_str)}" ## Calculate end index for highlight
            self.text_area.tag_remove("highlight", "1.0", tk.END)  # Remove previous highlights
            self.text_area.tag_add("highlight", start_idx, end_idx) ## Add new highlight
            self.text_area.tag_config("highlight", background="yellow") ## Configure highlight color
        
        listbox.bind("<Double-1>", goto_match) 
        tk.Button(results_window, text="Go to Match", command=goto_match).pack(pady=5)

    def save_file(self):
        """Save the current file data to the original file."""
        if not self.filename:
            messagebox.showerror("Error", "No file loaded")
            return
        try:
            with open(self.filename, 'wb') as f:
                f.write(self.file_data)
            messagebox.showinfo("Save", "File saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

    def save_file_as(self):
        """Save the current file data to a new file."""
        if not self.file_data:
            messagebox.showerror("Error", "No data to save")
            return
        new_filename = filedialog.asksaveasfilename(defaultextension=".bin",
                                                   filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if new_filename:
            try:
                with open(new_filename, 'wb') as f:
                    f.write(self.file_data)
                self.filename = new_filename
                messagebox.showinfo("Save", f"File saved as {new_filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    def run(self):
        """Start the Tkinter main event loop."""
        self.root.mainloop()

if __name__ == "__main__":
    # Entry point: create the Tkinter root window and run the app
    root = tk.Tk()
    app = HexEditor(root) 
    app.run()