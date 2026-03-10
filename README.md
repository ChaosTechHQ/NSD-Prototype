# ChaosTech NSD v18 - Neuro Swarm Disruptor

## Live Demo
https://nsd.chaostechdefensellc.com/chaostech_nsd_v18_ultimate.html

## Features
- 433/900/2.4/5.8GHz drone detection
- Real-time threat scoring
- Tactical radar visualization
- Autonomous AI engagement
- Production systemd deployment

## Local Deploy
```bash
cd ~/nsd-prototype
pip install -r requirements.txt
uvicorn nsd_api:app --host 0.0.0.0 --port 8000
```

## Production
sudo systemctl start nsd
