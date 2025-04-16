"""
CVAT Frame Checker GUI

This script provides a Tkinter-based GUI for interacting with the CVAT API.
It allows the user to:
 - Specify the CVAT server API URL.
 - Enter their credentials (username and password).
 - Select the scope of the query: Job, Task, or Project.
 - Specify the associated ID (e.g., Job ID, Task ID, or Project ID).
 - Choose whether to output detailed annotation data (one row per annotation instance)
   or non-detailed unique frame numbers.
 - Choose an output CSV file (with a file browse option).
 - Start processing the selected data via a button.
 - View real-time status updates in the GUI.
 - Exit the program using an "Exit" button.

The script uses the requests library to perform API calls to CVAT (authentication,
fetching annotations, tasks, or job details) and the csv module to write results.

Dependencies:
- Python 3.x
- requests (install via pip if not available: pip install requests)
- tkinter (usually part of standard Python installation)

Usage:
    Run this script directly. The GUI will appear and allow you to enter your settings.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import csv
import sys
import threading


# ---------------------- Backend Functions ---------------------- #
def get_auth_token(base_url, username, password):
    """
    Authenticate with the CVAT API and retrieve an access token.

    Parameters:
        base_url (str): The base URL of the CVAT API.
        username (str): The CVAT username.
        password (str): The CVAT password.

    Returns:
        str: The authentication token.

    Raises:
        Exception: If authentication fails.
    """
    login_url = f"{base_url}/auth/login"
    resp = requests.post(login_url, json={"username": username, "password": password})
    resp.raise_for_status()
    data = resp.json()
    token = data.get("key")
    if not token:
        raise Exception(f"Authentication failed. Server response: {data}")
    return token


def fetch_json(url, token):
    """
    Send a GET request to the specified URL with the authentication token,
    and return the JSON response.

    Parameters:
        url (str): The URL to send the GET request.
        token (str): The authentication token.

    Returns:
        dict: The JSON response from the API.

    Raises:
        HTTPError: If the API call fails.
    """
    headers = {"Authorization": f"Token {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp.json()


def process_annotation_data(annotation_data, task_id=None, job_id=None, detailed=False, label_map=None):
    """
    Process annotation data received from the CVAT API and extract frame information.

    Depending on the 'detailed' flag, the function either returns:
      - One row per annotation (with task_id, job_id, frame, label, and type)
        or
      - One row per unique frame number (with task_id, job_id, and frame) where at least
        one annotation exists.

    Parameters:
        annotation_data (dict): The JSON data containing annotations.
        task_id (int or None): The task ID associated with the annotations.
        job_id (int or None): The job ID associated with the annotations.
        detailed (bool): Flag indicating whether to output detailed annotation info.
        label_map (dict): A mapping from label ID to label name.

    Returns:
        list of dict: A list of dictionaries ready to be written to a CSV file.
    """
    if label_map is None:
        label_map = {}
    frames_with_ann = set()  # Set to collect unique frame numbers
    output_rows = []

    # Process tag annotations (frame-level annotations)
    for tag in annotation_data.get("tags", []):
        frame_num = tag.get("frame")
        if frame_num is None:
            continue
        if detailed:
            label_id = tag.get("label_id")
            label_name = label_map.get(label_id, f"Label {label_id}")
            output_rows.append({
                "task_id": task_id,
                "job_id": job_id,
                "frame": frame_num,
                "label": label_name,
                "type": "tag"
            })
        frames_with_ann.add(frame_num)

    # Process shape annotations (e.g., bounding boxes, polygons)
    for shape in annotation_data.get("shapes", []):
        frame_num = shape.get("frame")
        if frame_num is None:
            continue
        if detailed:
            label_id = shape.get("label_id")
            label_name = label_map.get(label_id, f"Label {label_id}")
            shape_type = shape.get("type") or "shape"
            output_rows.append({
                "task_id": task_id,
                "job_id": job_id,
                "frame": frame_num,
                "label": label_name,
                "type": shape_type
            })
        frames_with_ann.add(frame_num)

    # Process track annotations (for multi-frame tracked objects)
    for track in annotation_data.get("tracks", []):
        label_id = track.get("label_id")
        label_name = label_map.get(label_id, f"Label {label_id}")
        for shape in track.get("shapes", []):
            frame_num = shape.get("frame")
            if frame_num is None:
                continue
            if detailed:
                output_rows.append({
                    "task_id": task_id,
                    "job_id": job_id,
                    "frame": frame_num,
                    "label": label_name,
                    "type": f"track:{shape.get('type', 'shape')}"
                })
            frames_with_ann.add(frame_num)

    # For non-detailed mode, output one row per unique frame
    if not detailed:
        output_rows = [
            {"task_id": task_id, "job_id": job_id, "frame": frame_num}
            for frame_num in sorted(frames_with_ann)
        ]
    return output_rows


def build_label_map(task_detail):
    """
    Build a mapping from label ID to label name using task detail information.

    Parameters:
        task_detail (dict): The task detail JSON that includes label definitions.

    Returns:
        dict: Mapping of label IDs to label names.
    """
    label_map = {}
    for index, lbl in enumerate(task_detail.get("labels", [])):
        if isinstance(lbl, dict):
            label_map[lbl["id"]] = lbl["name"]
        else:
            # If the label is a simple string, use its index as key.
            label_map[index] = lbl
    return label_map


def process_annotations(base_url, username, password, scope, scope_id, detailed, output_file, status_callback):
    """
    Coordinates the processing of annotations from the CVAT API based on the selected scope
    (job, task, or project). Calls various helper functions to authenticate, retrieve data,
    process annotations, and write the results to a CSV file.

    Parameters:
        base_url (str): CVAT API URL.
        username (str): CVAT username.
        password (str): CVAT password.
        scope (str): One of "job", "task", or "project".
        scope_id (int): The identifier for the chosen scope.
        detailed (bool): Whether to output detailed annotation data.
        output_file (str): Path of the CSV file to output results.
        status_callback (function): A callback function to update status messages in the GUI.
    """
    try:
        status_callback("Authenticating...")
        token = get_auth_token(base_url, username, password)
        status_callback("Authentication successful.")

        frames_list = []
        label_map = {}

        if scope == "project":
            status_callback(f"Fetching tasks for Project ID {scope_id} ...")
            tasks_url = f"{base_url}/tasks?project_id={scope_id}&page_size=10000"
            tasks_data = fetch_json(tasks_url, token)
            tasks = tasks_data.get("results", tasks_data)
            if isinstance(tasks, dict):
                tasks = tasks.get("results", [])
            if not tasks:
                status_callback(f"No tasks found for project {scope_id}.")
            for task in tasks:
                task_id = task["id"] if isinstance(task, dict) else task
                status_callback(f"Processing Task ID {task_id} ...")
                ann_url = f"{base_url}/tasks/{task_id}/annotations"
                ann_data = fetch_json(ann_url, token)
                task_detail_url = f"{base_url}/tasks/{task_id}"
                task_detail = fetch_json(task_detail_url, token)
                label_map.update(build_label_map(task_detail))
                frames_list.extend(process_annotation_data(ann_data, task_id=task_id, job_id=None,
                                                           detailed=detailed, label_map=label_map))
        elif scope == "task":
            status_callback(f"Processing Task ID {scope_id} ...")
            ann_url = f"{base_url}/tasks/{scope_id}/annotations"
            ann_data = fetch_json(ann_url, token)
            task_detail_url = f"{base_url}/tasks/{scope_id}"
            task_detail = fetch_json(task_detail_url, token)
            label_map.update(build_label_map(task_detail))
            frames_list.extend(process_annotation_data(ann_data, task_id=scope_id, job_id=None,
                                                       detailed=detailed, label_map=label_map))
        else:  # scope == "job"
            status_callback(f"Processing Job ID {scope_id} ...")
            ann_url = f"{base_url}/jobs/{scope_id}/annotations"
            ann_data = fetch_json(ann_url, token)
            job_detail_url = f"{base_url}/jobs/{scope_id}"
            job_detail = fetch_json(job_detail_url, token)
            task_id = job_detail.get("task_id") or job_detail.get("task")
            if task_id:
                task_detail_url = f"{base_url}/tasks/{task_id}"
                task_detail = fetch_json(task_detail_url, token)
                label_map.update(build_label_map(task_detail))
            frames_list.extend(process_annotation_data(ann_data, task_id=task_id, job_id=scope_id,
                                                       detailed=detailed, label_map=label_map))

        # Write the processed frame data into the output CSV file
        status_callback("Writing results to CSV...")
        if detailed:
            fieldnames = ["task_id", "job_id", "frame", "label", "type"]
        else:
            fieldnames = ["task_id", "job_id", "frame"]
        with open(output_file, mode="w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in frames_list:
                writer.writerow(row)
        status_callback(f"Processing complete. Results written to {output_file}")

    except Exception as e:
        status_callback(f"Error: {str(e)}")
        messagebox.showerror("Error", str(e))


# ------------------------ GUI Code using Tkinter ------------------------ #
class CVATFrameCheckerGUI(tk.Tk):
    """
    Tkinter-based GUI for the CVAT Frame Checker. Users can input CVAT settings,
    choose the scope of annotation processing, and start processing by clicking
    the "Start Processing" button. There is also an "Exit" button to close the program.
    """

    def __init__(self):
        super().__init__()
        self.title("CVAT Frame Checker")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        """
        Create and grid all the widgets in the GUI.
        """
        # CVAT Server URL
        url_frame = ttk.Frame(self)
        url_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        ttk.Label(url_frame, text="CVAT API URL:").grid(row=0, column=0, sticky="w")
        self.url_entry = ttk.Entry(url_frame, width=40)
        self.url_entry.insert(0, "http://localhost:8080/api")
        self.url_entry.grid(row=0, column=1, padx=5)

        # Credentials: Username and Password
        cred_frame = ttk.Frame(self)
        cred_frame.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky="w")
        self.username_entry = ttk.Entry(cred_frame, width=20)
        self.username_entry.insert(0, "Monitor")
        self.username_entry.grid(row=0, column=1, padx=5)

        ttk.Label(cred_frame, text="Password:").grid(row=0, column=2, sticky="w")
        self.password_entry = ttk.Entry(cred_frame, show="*", width=20)
        self.password_entry.insert(0, "Streetscan123")
        self.password_entry.grid(row=0, column=3, padx=5)

        # Scope selection: Job, Task, or Project.
        scope_frame = ttk.LabelFrame(self, text="Scope")
        scope_frame.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.scope_var = tk.StringVar(value="job")
        ttk.Radiobutton(scope_frame, text="Job", variable=self.scope_var, value="job",
                        command=self.update_scope).grid(row=0, column=0, padx=5, pady=2, sticky="w")
        ttk.Radiobutton(scope_frame, text="Task", variable=self.scope_var, value="task",
                        command=self.update_scope).grid(row=0, column=1, padx=5, pady=2, sticky="w")
        ttk.Radiobutton(scope_frame, text="Project", variable=self.scope_var, value="project",
                        command=self.update_scope).grid(row=0, column=2, padx=5, pady=2, sticky="w")

        # Scope ID input (Job ID, Task ID, or Project ID) based on the selected scope.
        self.scope_id_frame = ttk.Frame(scope_frame)
        self.scope_id_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        self.scope_id_label = ttk.Label(self.scope_id_frame, text="Job ID:")
        self.scope_id_label.grid(row=0, column=0, sticky="w")
        self.scope_id_entry = ttk.Entry(self.scope_id_frame, width=10)
        self.scope_id_entry.insert(0, "157")
        self.scope_id_entry.grid(row=0, column=1, padx=5)

        # Detailed mode checkbox
        detailed_frame = ttk.Frame(self)
        detailed_frame.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.detailed_var = tk.BooleanVar(value=False)
        self.detailed_check = ttk.Checkbutton(detailed_frame, text="Detailed Output", variable=self.detailed_var)
        self.detailed_check.grid(row=0, column=0, sticky="w")

        # Output file selector
        output_frame = ttk.Frame(self)
        output_frame.grid(row=4, column=0, padx=10, pady=5, sticky="w")
        ttk.Label(output_frame, text="Output CSV File:").grid(row=0, column=0, sticky="w")
        self.output_entry = ttk.Entry(output_frame, width=30)
        self.output_entry.insert(0, "job157.csv")
        self.output_entry.grid(row=0, column=1, padx=5)
        self.browse_button = ttk.Button(output_frame, text="Browse...", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=5)

        # Buttons for Starting Processing and Exiting the application.
        button_frame = ttk.Frame(self)
        button_frame.grid(row=5, column=0, padx=10, pady=10, sticky="w")
        self.start_button = ttk.Button(button_frame, text="Start Processing", command=self.start_processing)
        self.start_button.grid(row=0, column=0, padx=5)
        self.exit_button = ttk.Button(button_frame, text="Exit", command=self.destroy)
        self.exit_button.grid(row=0, column=1, padx=5)

        # Status label to display messages to the user.
        self.status_label = ttk.Label(self, text="Ready", foreground="blue")
        self.status_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")

    def update_scope(self):
        """
        Update the label and default value of the scope ID field based on the
        selected scope (Job, Task, or Project).
        """
        scope = self.scope_var.get()
        if scope == "job":
            self.scope_id_label.config(text="Job ID:")
            self.scope_id_entry.delete(0, tk.END)
            self.scope_id_entry.insert(0, "157")
        elif scope == "task":
            self.scope_id_label.config(text="Task ID:")
            self.scope_id_entry.delete(0, tk.END)
        elif scope == "project":
            self.scope_id_label.config(text="Project ID:")
            self.scope_id_entry.delete(0, tk.END)

    def browse_file(self):
        """
        Open a file dialog to let the user select a filename for the output CSV.
        """
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if file:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, file)

    def update_status(self, message):
        """
        Update the GUI status label with the provided message.

        Parameters:
            message (str): The status message to display.
        """
        self.status_label.config(text=message)
        self.update_idletasks()  # Immediately refresh the GUI

    def start_processing(self):
        """
        Retrieve all user inputs from the GUI, validate them, and start the annotation
        processing in a separate thread to keep the GUI responsive.
        """
        base_url = self.url_entry.get().strip().rstrip("/")
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        scope = self.scope_var.get()
        scope_id = self.scope_id_entry.get().strip()
        detailed = self.detailed_var.get()
        output_file = self.output_entry.get().strip()

        if not (base_url and username and password and scope_id and output_file):
            messagebox.showerror("Missing Info", "Please fill in all fields.")
            return

        try:
            scope_id = int(scope_id)
        except ValueError:
            messagebox.showerror("Invalid ID", "Scope ID must be an integer.")
            return

        # Disable Start Processing button to prevent multiple invocations.
        self.start_button.config(state="disabled")
        self.update_status("Starting processing...")

        # Run the processing function in a separate thread so the GUI remains responsive.
        thread = threading.Thread(target=process_annotations,
                                  args=(base_url, username, password, scope, scope_id,
                                        detailed, output_file, self.update_status))
        thread.start()
        # Monitor thread and re-enable the button once finished.
        self.after(100, lambda: self.check_thread(thread))

    def check_thread(self, thread):
        """
        Check if the processing thread is still running. Once the thread completes,
        re-enable the Start Processing button.

        Parameters:
            thread (Thread): The thread running the annotation processing.
        """
        if thread.is_alive():
            self.after(100, lambda: self.check_thread(thread))
        else:
            self.start_button.config(state="normal")


if __name__ == "__main__":
    app = CVATFrameCheckerGUI()
    app.mainloop()
