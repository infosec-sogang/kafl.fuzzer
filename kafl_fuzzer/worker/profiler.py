import time
import csv

csv_file = None
csv_writer = None

def init(csv_path: str):
    global csv_file, csv_writer
    csv_file = open(csv_path, "w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["StepName", "StartTime", "EndTime", "Duration_ms"])

def time_start() -> float:
    """
    측정 시작 시점(초) 반환
    """
    return time.perf_counter()

def time_end(step_name: str, start_time: float):
    """
    측정 종료 → CSV에 기록
    """
    global csv_writer
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000.0

    csv_writer.writerow([
        step_name,
        f"{start_time:.6f}",
        f"{end_time:.6f}",
        f"{duration_ms:.3f}"
    ])

def close():
    global csv_file
    if csv_file:
        csv_file.close()
        csv_file = None
