from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import os
from datetime import datetime
import shutil
import mimetypes

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Admin email - hardcoded
ADMIN_EMAIL = "rohitkumarsoni199977777@gmail.com"

# Create uploads folder
os.makedirs('uploads', exist_ok=True)

# Initialize database with correct schema
def init_db():
    conn = sqlite3.connect('filemanager.db')
    c = conn.cursor()
    # Drop old table if exists to recreate with correct schema
    c.execute('DROP TABLE IF EXISTS files')
    # Create table with email column
    c.execute('''CREATE TABLE files
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      filename TEXT NOT NULL,
                      filepath TEXT NOT NULL,
                      filetype TEXT NOT NULL,
                      size INTEGER,
                      uploaded_at TEXT NOT NULL,
                      email TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r") as f:
        return f.read()

@app.get("/api/files")
async def get_files():
    conn = sqlite3.connect('filemanager.db')
    c = conn.cursor()
    c.execute('SELECT * FROM files ORDER BY uploaded_at DESC')
    files = c.fetchall()
    conn.close()
    files_list = []
    for file in files:
        files_list.append({
            'id': file[0],
            'filename': file[1],
            'filepath': file[2],
            'filetype': file[3],
            'size': file[4],
            'uploaded_at': file[5],
            'email': file[6]
        })
    return {'files': files_list}

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    email: str = Form(default="anonymous@user.com")
):
    # Create unique filename
    filename = file.filename
    filepath = os.path.join('uploads', filename)
    counter = 1
    base_name, ext = os.path.splitext(filename)
    while os.path.exists(filepath):
        filename = f"{base_name}_{counter}{ext}"
        filepath = os.path.join('uploads', filename)
        counter += 1

    # Save file
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    filesize = os.path.getsize(filepath)
    filetype = filename.split('.')[-1].upper() if '.' in filename else 'UNKNOWN'
    upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Save to database
    conn = sqlite3.connect('filemanager.db')
    c = conn.cursor()
    c.execute('''INSERT INTO files (filename, filepath, filetype, size, uploaded_at, email)
                     VALUES (?, ?, ?, ?, ?, ?)''',
              (filename, filepath, filetype, filesize, upload_date, email))
    conn.commit()
    file_id = c.lastrowid
    conn.close()

    return {
        'success': True,
        'message': 'File uploaded successfully!',
        'id': file_id
    }

@app.put("/api/files/{file_id}/update")
async def update_file(
    file_id: int,
    email: str = Form(...),
    file: UploadFile = File(...)
):
    # Check admin email
    if email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Access denied. Only admin can update files.")

    # Check if file exists
    conn = sqlite3.connect('filemanager.db')
    c = conn.cursor()
    c.execute('SELECT filename, filepath FROM files WHERE id = ?', (file_id,))
    result = c.fetchone()
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")

    old_filename, old_filepath = result

    # Overwrite the old file with new content (start from old location)
    with open(old_filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Handle filename change if new filename differs from old
    new_filename = file.filename
    if new_filename != old_filename:
        # Generate new filepath based on new filename, handling conflicts
        new_filepath = os.path.join('uploads', new_filename)
        counter = 1
        base_name, ext = os.path.splitext(new_filename)
        while os.path.exists(new_filepath):
            new_filename = f"{base_name}_{counter}{ext}"
            new_filepath = os.path.join('uploads', new_filename)
            counter += 1

        # Rename the file to new location
        os.rename(old_filepath, new_filepath)

        # Update DB with new filename and filepath
        filetype = new_filename.split('.')[-1].upper() if '.' in new_filename else 'UNKNOWN'
        filesize = os.path.getsize(new_filepath)
        c.execute('''UPDATE files SET filename=?, filepath=?, filetype=?, size=?
                         WHERE id=?''',
                  (new_filename, new_filepath, filetype, filesize, file_id))
    else:
        # Same filename: just update size and filetype if needed
        filetype = new_filename.split('.')[-1].upper() if '.' in new_filename else 'UNKNOWN'
        filesize = os.path.getsize(old_filepath)
        c.execute('''UPDATE files SET filetype=?, size=?
                         WHERE id=?''',
                  (filetype, filesize, file_id))

    conn.commit()
    conn.close()

    return {'success': True, 'message': 'File updated successfully!'}

@app.delete("/api/files/{file_id}/delete")
async def delete_file(file_id: int, email: str):
    # Check admin email
    if email != ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Access denied. Only admin can delete files.")

    # Check if file exists
    conn = sqlite3.connect('filemanager.db')
    c = conn.cursor()
    c.execute('SELECT filepath FROM files WHERE id = ?', (file_id,))
    result = c.fetchone()
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")

    filepath = result[0]

    # Delete file from filesystem
    if os.path.exists(filepath):
        os.remove(filepath)

    # Delete from database
    c.execute('DELETE FROM files WHERE id = ?', (file_id,))
    conn.commit()
    conn.close()

    return {'success': True, 'message': 'File deleted successfully!'}

@app.get("/api/files/{file_id}/download")
async def download_file(file_id: int):
    conn = sqlite3.connect('filemanager.db')
    c = conn.cursor()
    c.execute('SELECT filename, filepath FROM files WHERE id = ?', (file_id,))
    result = c.fetchone()
    conn.close()
    if not result:
        raise HTTPException(status_code=404, detail="File not found")

    filename, filepath = result
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found on server")

    # Determine MIME type for inline viewing
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        mime_type = 'application/octet-stream'

    # Headers for inline viewing (no forced download)
    headers = {"Content-Disposition": f"inline; filename={filename}"}

    return FileResponse(
        filepath,
        filename=filename,
        media_type=mime_type,
        headers=headers
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=0000)