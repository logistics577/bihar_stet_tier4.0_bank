import aiohttp.web as web
import asyncio
import os
from datetime import datetime
import mimetypes
from aiofiles import open as aioopen
import logging
import sys
import hashlib
from pathlib import Path
import re
from supabase import create_client, Client

# ────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────
ADMIN_EMAIL = "zapierobroy77777559977@gmail.com"
SUPABASE_URL = "https://obnhesobzgppiidigdtu.supabase.co"
# !!! IMPORTANT !!! Use service_role key in production - never publishable key
SUPABASE_KEY = "sb_publishable_-zpPTE45VhRROAZOV0xxFg_iTMVSYLA" # ← CHANGE THIS
UPLOAD_DIR = Path("uploads")
LOG_DIR = Path("logs")
MAX_FILE_SIZE = 100 * 1024 * 1024 # 100 MB
# Create directories
UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-7s] %(name)-12s %(funcName)18s:%(lineno)4d → %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "filemanager.log"),
        logging.FileHandler(LOG_DIR / "operations.log")
    ]
)
logger = logging.getLogger("filemanager")
operation_logger = logging.getLogger("operations")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ────────────────────────────────────────────────
# HELPERS
# ────────────────────────────────────────────────
def safe_filename(original: str) -> str:
    """Sanitize filename - prevent path traversal & dangerous chars"""
    name = Path(original).name
    name = re.sub(r'[^a-zA-Z0-9._\-\u0600-\u06FF\s]', '_', name)
    if len(name) > 180:
        base, ext = os.path.splitext(name)
        name = base[:170] + ext
    return name

def calculate_file_hash(filepath: Path | str, algorithm="md5") -> str | None:
    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Hash failed {filepath}: {e}")
        return None

def log_operation(operation: str, file_id=None, filename=None, user_email=None,
                  success=True, details=None, error_message=None):
    try:
        data = {
            'operation': operation.upper(),
            'file_id': file_id,
            'filename': filename,
            'user_email': user_email,
            'operation_time': datetime.utcnow().isoformat(),
            'details': details,
            'success': success,
            'error_message': error_message
        }
        supabase.table('operations_log').insert(data).execute()
        msg = f"{operation:8} | {filename or '-':<35} | {user_email or '-':<28} | {'OK' if success else 'FAIL'}"
        if details: msg += f" | {details}"
        if error_message: msg += f" | {error_message}"
        if success:
            operation_logger.info(msg)
        else:
            operation_logger.error(msg)
    except Exception as e:
        logger.error(f"Operation logging failed: {e}")

# Wrapper to run Supabase sync calls in thread (non-blocking)
async def run_supabase_sync(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

# JSON Error Response Helper
def json_error(message, status=500):
    return web.json_response({"success": False, "message": message}, status=status)

# ────────────────────────────────────────────────
# MIDDLEWARE FOR JSON ERRORS (FIXED - ONLY FOR EXCEPTIONS)
# ────────────────────────────────────────────────
async def json_error_middleware(app, handler):
    async def middleware_handler(request):
        try:
            response = await handler(request)
            return response  # Let successful responses through unchanged
        except web.HTTPException as ex:
            return json_error(str(ex), ex.status)
        except Exception as ex:
            logger.error(f"Unhandled error: {ex}", exc_info=True)
            return json_error(f"Internal server error: {str(ex)}", 500)
    return middleware_handler

# ────────────────────────────────────────────────
# ROUTES - ALL IMPLEMENTED
# ────────────────────────────────────────────────
async def read_root(request):
    try:
        async with aioopen("index.html", "r", encoding="utf-8") as f:
            return web.Response(text=await f.read(), content_type='text/html')
    except FileNotFoundError:
        return web.Response(text="<h1>index.html not found</h1>", status=404)
    except Exception as e:
        logger.error(f"Root page error: {e}")
        raise web.HTTPInternalServerError()

async def get_files(request):
    try:
        res = await run_supabase_sync(
            supabase.table('files')
            .select("id, filename, filepath, filetype, size, uploaded_at, email, download_count, last_accessed")
            .eq('status', 'active')
            .order('uploaded_at', desc=True)
            .execute
        )
        files = res.data or []
        total_size = sum(Path(f['filepath']).stat().st_size for f in files if Path(f['filepath']).exists())
        return web.json_response({
            "success": True,
            "files": files,
            "total_files": len(files),
            "total_size_bytes": total_size
        })
    except Exception as e:
        logger.error(f"get_files error: {e}", exc_info=True)
        raise

async def upload_file(request):
    original_name = None  # Initialize early for error logging
    email = "anonymous@user.com"
    try:
        reader = await request.multipart()
        file_content = bytearray()
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "file":
                original_name = safe_filename(part.filename)
                async for chunk in part:
                    file_content.extend(chunk)
            elif part.name == "email":
                email = (await part.text()).strip()[:180]
        
        if not original_name or not file_content:
            log_operation("UPLOAD", user_email=email, success=False, error_message="Missing file")
            return json_error("File is required", 400)
        
        file_size = len(file_content)
        
        # Check for empty file
        if file_size == 0:
            log_operation("UPLOAD", filename=original_name, user_email=email, success=False, error_message="Empty file")
            return json_error("Empty file not allowed. Please upload a file with content.", 400)
        
        if file_size > MAX_FILE_SIZE:
            log_operation("UPLOAD", filename=original_name, user_email=email, success=False, error_message="File too large")
            return json_error(f"File too large. Maximum size is {MAX_FILE_SIZE//1024//1024}MB", 413)
        
        # Check if file with same name already exists
        filepath = UPLOAD_DIR / original_name
        if filepath.exists():
            log_operation("UPLOAD", filename=original_name, user_email=email, success=False, error_message="File already exists")
            return json_error(f"File '{original_name}' already exists. Please rename your file or delete the existing one first.", 409)
        
        # Save the file
        async with aioopen(filepath, "wb") as f:
            await f.write(file_content)
        
        actual_size = filepath.stat().st_size
        if actual_size != file_size:
            filepath.unlink(missing_ok=True)
            raise RuntimeError("Size mismatch after save")
        
        file_hash = calculate_file_hash(filepath)
        data = {
            "filename": original_name,
            "filepath": str(filepath),
            "filetype": Path(original_name).suffix.lstrip('.').upper() or "FILE",
            "size": actual_size,
            "uploaded_at": datetime.utcnow().isoformat(),
            "email": email,
            "md5_hash": file_hash,
            "last_accessed": datetime.utcnow().isoformat(),
            "status": "active",
            "download_count": 0
        }
        
        # Non-blocking DB insert
        result = await run_supabase_sync(supabase.table('files').insert(data).execute)
        file_id = result.data[0]["id"]
        
        log_operation("UPLOAD", file_id, original_name, email, True,
                      f"Size: {actual_size:,} Hash: {file_hash}")
        
        return web.json_response({
            "success": True,
            "message": f"File '{original_name}' uploaded successfully",
            "id": file_id,
            "filename": original_name,
            "size": actual_size,
            "hash": file_hash
        })
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        log_operation("UPLOAD", filename=original_name, user_email=email,
                      success=False, error_message=str(e))
        raise

async def download_file(request):
    try:
        file_id = int(request.match_info['file_id'])
        # Non-blocking DB query
        res = await run_supabase_sync(
            supabase.table('files')
            .select("filename, filepath, size, md5_hash, download_count")
            .eq('id', file_id)
            .eq('status', 'active')
            .single()
            .execute
        )
        if not res.data:
            raise web.HTTPNotFound(text="File not found or deleted")
        file = res.data
        path = Path(file['filepath'])
        if not path.exists():
            log_operation("DOWNLOAD", file_id, file['filename'], None, False, error_message="File missing on disk")
            raise web.HTTPNotFound(text="File no longer exists")
        mime, _ = mimetypes.guess_type(path.name)
        mime = mime or 'application/octet-stream'
        # Non-blocking download count increment
        current_count = file.get('download_count', 0)
        await run_supabase_sync(
            supabase.table('files')
            .update({"download_count": current_count + 1, "last_accessed": datetime.utcnow().isoformat()})
            .eq('id', file_id)
            .execute
        )
        log_operation("DOWNLOAD", file_id, file['filename'], success=True,
                      details=f"Size: {file['size']:,}")
        return web.FileResponse(
            path,
            headers={
                "Content-Disposition": f'attachment; filename="{file["filename"]}"',
                "Content-Type": mime,
                "Content-Length": str(file['size']),
                "X-File-Hash": file["md5_hash"] or ""
            }
        )
    except web.HTTPException:
        raise
    except ValueError:
        raise web.HTTPBadRequest(text="Invalid file ID")
    except Exception as e:
        logger.error(f"Download error: {e}")
        raise

async def delete_file(request):
    try:
        file_id = int(request.match_info['file_id'])
    except (ValueError, KeyError):
        return json_error("Invalid file ID", 400)
    
    email = request.query.get('email', '').strip()
    
    if not email:
        return json_error("Email is required for deletion", 400)
    
    if email != ADMIN_EMAIL:
        log_operation("DELETE", file_id, user_email=email, success=False, error_message="Unauthorized - not admin email")
        return json_error(f"Access denied. Only admin can delete files.", 403)
    
    try:
        # Non-blocking DB query
        res = await run_supabase_sync(
            supabase.table('files')
            .select("filename, filepath, size")
            .eq('id', file_id)
            .eq('status', 'active')
            .single()
            .execute
        )
        if not res.data:
            raise web.HTTPNotFound()
        file = res.data
        path = Path(file['filepath'])
        existed = path.exists()
        if existed:
            path.unlink(missing_ok=True)
        # Non-blocking DB update
        await run_supabase_sync(
            supabase.table('files')
            .update({"status": "deleted"})
            .eq('id', file_id)
            .execute
        )
        log_operation("DELETE", file_id, file['filename'], email, True,
                      f"Size: {file['size']:,} Disk existed: {existed}")
        return web.json_response({
            "success": True,
            "message": f"File '{file['filename']}' deleted successfully"
        })
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete failed: {e}")
        log_operation("DELETE", file_id, success=False, error_message=str(e))
        return json_error(f"Failed to delete file: {str(e)}", 500)

async def update_file(request):
    try:
        file_id = int(request.match_info['file_id'])
    except (ValueError, KeyError):
        return json_error("Invalid file ID", 400)
    
    try:
        reader = await request.multipart()
        new_content = bytearray()
        new_filename = None
        email = None
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "file":
                new_filename = safe_filename(part.filename)
                async for chunk in part:
                    new_content.extend(chunk)
            elif part.name == "email":
                email = (await part.text()).strip()
        
        if not email:
            return json_error("Email is required for updating files", 400)
        
        if email != ADMIN_EMAIL:
            log_operation("UPDATE", file_id, user_email=email, success=False, error_message="Unauthorized - not admin email")
            return json_error(f"Access denied. Only admin can update files.", 403)
        
        if not new_content or not new_filename:
            return json_error("File is required for update", 400)
        
        if len(new_content) > MAX_FILE_SIZE:
            return json_error(f"File too large. Maximum size is {MAX_FILE_SIZE//1024//1024}MB", 413)
        # Non-blocking DB query for old file
        old = await run_supabase_sync(
            supabase.table('files')
            .select("filename, filepath")
            .eq('id', file_id)
            .eq('status', 'active')
            .single()
            .execute
        )
        if not old.data:
            log_operation("UPDATE", file_id, user_email=email, success=False, error_message="File not found")
            return json_error("File not found or already deleted", 404)
        old_filepath = Path(old.data['filepath'])
        # Overwrite with new content
        async with aioopen(old_filepath, "wb") as f:
            await f.write(new_content)
        new_size = old_filepath.stat().st_size
        new_hash = calculate_file_hash(old_filepath)
        # Non-blocking DB update
        await run_supabase_sync(
            supabase.table('files')
            .update({
                "filename": new_filename,
                "filetype": Path(new_filename).suffix.lstrip('.').upper() or "FILE",
                "size": new_size,
                "md5_hash": new_hash,
                "last_accessed": datetime.utcnow().isoformat()
            })
            .eq('id', file_id)
            .execute
        )
        log_operation("UPDATE", file_id, new_filename, email, True,
                      f"New size: {new_size:,} Hash: {new_hash}")
        return web.json_response({
            "success": True,
            "message": f"File '{new_filename}' updated successfully",
            "filename": new_filename,
            "size": new_size,
            "hash": new_hash
        })
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update error: {e}")
        log_operation("UPDATE", file_id, success=False, error_message=str(e))
        return json_error(f"Failed to update file: {str(e)}", 500)

async def save_url(request):
    try:
        reader = await request.multipart()
        url = None
        title = None
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "url":
                url = (await part.text()).strip()
            elif part.name == "title":
                title = (await part.text()).strip()
        if not url:
            raise web.HTTPBadRequest(text="url is required")
        # Default title to URL if not provided
        if not title:
            title = url
        
        # Generate unique short code (5 characters from timestamp + random)
        import random
        import string
        max_attempts = 10
        short_code = None
        
        for attempt in range(max_attempts):
            # Generate short code: timestamp hash + random chars
            timestamp = str(int(datetime.utcnow().timestamp() * 1000))
            random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=3))
            short_code = hashlib.md5(f"{timestamp}{random_part}".encode()).hexdigest()[:5]
            
            # Check if short_code already exists
            existing = await run_supabase_sync(
                supabase.table('urls')
                .select("id")
                .eq('short_code', short_code)
                .execute
            )
            
            if not existing.data:
                break  # Found unique short_code
            short_code = None
        
        if not short_code:
            raise RuntimeError("Could not generate unique short code after multiple attempts")
        
        # Non-blocking DB insert (allow same URLs with different short codes)
        result = await run_supabase_sync(
            supabase.table('urls')
            .insert({
                "url": url,
                "title": title,
                "short_code": short_code,
                "created_at": datetime.utcnow().isoformat()
            })
            .execute
        )
        return web.json_response({
            "success": True,
            "id": result.data[0]["id"],
            "short_code": short_code,
            "message": "URL saved"
        })
    except Exception as e:
        logger.error(f"Save URL error: {e}")
        raise

async def get_urls(request):
    try:
        # Non-blocking DB query
        res = await run_supabase_sync(
            supabase.table('urls')
            .select("id, url, title, short_code, created_at")
            .order('created_at', desc=True)
            .execute
        )
        return web.json_response({
            "success": True,
            "urls": res.data or [],
            "total": len(res.data or [])
        })
    except Exception as e:
        logger.error(f"Get URLs error: {e}")
        raise

async def url_redirect(request):
    url_id = int(request.match_info['url_id'])
    try:
        # Non-blocking DB query
        res = await run_supabase_sync(
            supabase.table('urls')
            .select("url")
            .eq('id', url_id)
            .single()
            .execute
        )
        if not res.data:
            raise web.HTTPNotFound()
        raise web.HTTPFound(location=res.data["url"])
    except web.HTTPException:
        raise
    except ValueError:
        raise web.HTTPBadRequest(text="Invalid URL ID")
    except Exception as e:
        logger.error(f"URL redirect error: {e}")
        raise

async def delete_url(request):
    try:
        url_id = int(request.match_info['url_id'])
    except (ValueError, KeyError):
        return json_error("Invalid URL ID", 400)
    
    email = request.query.get('email', '').strip()
    
    if not email:
        return json_error("Email is required for deletion", 400)
    
    if email != ADMIN_EMAIL:
        logger.warning(f"Unauthorized URL delete attempt by {email} for URL ID {url_id}")
        return json_error(f"Access denied. Only admin can delete URLs.", 403)
    
    try:
        # Non-blocking DB query to get URL details
        res = await run_supabase_sync(
            supabase.table('urls')
            .select("id, url, title")
            .eq('id', url_id)
            .single()
            .execute
        )
        
        if not res.data:
            return json_error("URL not found", 404)
        
        url_data = res.data
        
        # Delete the URL
        await run_supabase_sync(
            supabase.table('urls')
            .delete()
            .eq('id', url_id)
            .execute
        )
        
        logger.info(f"URL deleted: ID={url_id}, Title='{url_data['title']}', By={email}")
        
        return web.json_response({
            "success": True,
            "message": f"URL '{url_data['title']}' deleted successfully"
        })
    
    except web.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete URL failed: {e}")
        return json_error(f"Failed to delete URL: {str(e)}", 500)

# ────────────────────────────────────────────────
# APP SETUP
# ────────────────────────────────────────────────
def create_app():
    app = web.Application(client_max_size=MAX_FILE_SIZE + 2*1024*1024)
    # Add JSON error middleware (now fixed - only catches exceptions)
    app.middlewares.append(json_error_middleware)
    app.router.add_get('/', read_root)
    app.router.add_get('/api/files', get_files)
    app.router.add_post('/api/upload', upload_file)
    app.router.add_put('/api/files/{file_id}/update', update_file)
    app.router.add_delete('/api/files/{file_id}/delete', delete_file)
    app.router.add_get('/api/files/{file_id}/download', download_file)
    app.router.add_post('/api/save-url', save_url)
    app.router.add_get('/api/urls', get_urls)
    app.router.add_delete('/api/urls/{url_id}/delete', delete_url)
    app.router.add_get('/api/url/{url_id}', url_redirect)
    logger.info("All routes registered:")
    for r in app.router.routes():
        logger.info(f" {r.method:6} {r.resource.canonical}")
    return app

async def main():
    logger.info("=" * 80)
    logger.info(" FILE MANAGER SERVER - FULL VERSION ".center(80, "="))
    logger.info(f" Upload dir : {UPLOAD_DIR.absolute()}")
    logger.info(f" Max file size : {MAX_FILE_SIZE//1024//1024} MB")
    logger.info("=" * 80)
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 9000)
    await site.start()
    logger.info("Server running → http://0.0.0.0:9000")
    logger.info("Press Ctrl+C to stop")
    await asyncio.Future() # forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)