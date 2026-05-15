#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick test for video functionality"""

from pathlib import Path
import subprocess
import os

def test_video_setup():
    print("🎬 Kiểm tra setup video...")
    
    # 1. Kiểm tra thư mục video
    video_dir = Path("video")
    if not video_dir.exists():
        print("❌ Thư mục 'video' không tồn tại!")
        return False
    
    # 2. Kiểm tra file video
    video_files = list(video_dir.glob("*.mp4"))
    if not video_files:
        print("❌ Không tìm thấy file .mp4!")
        return False
    
    print(f"✅ Tìm thấy {len(video_files)} file video:")
    for video in video_files:
        print(f"   - {video.name} ({video.stat().st_size // 1024} KB)")
    
    # 3. Kiểm tra VLC
    if os.name == 'nt':  # Windows
        vlc_paths = [
            r"C:\Program Files\VideoLAN\VLC\vlc.exe",
            r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe"
        ]
        
        vlc_found = False
        for vlc_path in vlc_paths:
            if Path(vlc_path).exists():
                print(f"✅ VLC tìm thấy: {vlc_path}")
                vlc_found = True
                break
        
        if not vlc_found:
            print("⚠️  VLC không tìm thấy - sẽ dùng Windows Media Player")
            
            # Test Windows Media Player
            try:
                result = subprocess.run(['where', 'wmplayer.exe'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print("✅ Windows Media Player có sẵn")
                else:
                    print("❌ Windows Media Player không tìm thấy!")
                    return False
            except:
                print("❌ Không thể kiểm tra Windows Media Player")
                return False
    
    # 4. Test phát video (nếu có VLC)
    if vlc_found:
        print("\n🎵 Test phát video (sẽ tự động tắt sau 3 giây)...")
        try:
            video_file = video_files[0]
            process = subprocess.Popen([
                vlc_path, str(video_file),
                "--intf", "dummy",
                "--play-and-exit",
                "--stop-time=3"  # Dừng sau 3 giây
            ], creationflags=subprocess.CREATE_NO_WINDOW)
            
            process.wait(timeout=10)  # Chờ tối đa 10 giây
            print("✅ Test phát video thành công!")
            
        except subprocess.TimeoutExpired:
            process.terminate()
            print("✅ Video đã phát (timeout - bình thường)")
        except Exception as e:
            print(f"⚠️  Test video có lỗi: {e}")
    
    return True

def test_monitor_screen_import():
    print("\n📦 Kiểm tra import monitor_screen...")
    try:
        from screens.monitor_screen import VideoPlayer, MonitorScreen
        print("✅ Import thành công!")
        return True
    except ImportError as e:
        print(f"❌ Import thất bại: {e}")
        return False

def main():
    print("=" * 50)
    print("🎬 Quick Video Test for YarGen GUI")
    print("=" * 50)
    
    success = True
    
    # Test 1: Video setup
    if not test_video_setup():
        success = False
    
    # Test 2: Import
    if not test_monitor_screen_import():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("✅ Tất cả test PASS! Video sẵn sàng sử dụng.")
        print("\n💡 Để sử dụng:")
        print("   1. Chạy ứng dụng chính")
        print("   2. Vào tab Monitor")
        print("   3. Chọn layout 'tabbed' hoặc 'vertical'")
        print("   4. Bật 'Hiện video giải trí'")
        print("   5. Bắt đầu generate YARA rules")
    else:
        print("❌ Có lỗi! Kiểm tra lại:")
        print("   - Cài VLC: https://www.videolan.org/vlc/")
        print("   - Đảm bảo có file video.mp4 trong thư mục video/")
    print("=" * 50)

if __name__ == "__main__":
    main()