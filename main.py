import asyncio
import logging
import json
from typing import AsyncGenerator
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from models import (
    AttackPathRequest, AttackPathResponse, StreamingPathUpdate
)
from attack_path_service import attack_path_service
from config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Attack Path Generation LLM Agent",
    description="AI-powered attack path generation and risk assessment service",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variable to store streaming updates
streaming_updates = []


@app.on_event("startup")
async def startup_event():
    """Initialize the service on startup"""
    try:
        await attack_path_service.initialize()
        logger.info("Application started successfully")
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    try:
        await attack_path_service.close()
        logger.info("Application shutdown successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Attack Path Generation LLM Agent",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "attack_path_generation"
    }


@app.post("/api/v1/attack-paths", response_model=AttackPathResponse)
async def generate_attack_paths(request: AttackPathRequest):
    """Generate attack paths for a domain (non-streaming)"""
    try:
        logger.info(f"Generating attack paths for domain: {request.domain}")
        
        # Generate attack paths without streaming
        response = await attack_path_service.generate_attack_paths(
            domain=request.domain,
            top_n=request.top_n or settings.DEFAULT_TOP_N
        )
        
        return response
        
    except ValueError as e:
        logger.warning(f"Validation error for domain {request.domain}: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error generating attack paths for {request.domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.post("/api/v1/attack-paths/stream")
async def generate_attack_paths_stream(request: AttackPathRequest):
    """Generate attack paths with streaming updates"""
    try:
        logger.info(f"Generating attack paths with streaming for domain: {request.domain}")
        
        # Clear previous streaming updates
        global streaming_updates
        streaming_updates = []
        
        # Create streaming response
        return StreamingResponse(
            _generate_attack_paths_stream(request),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Content-Type": "text/plain; charset=utf-8"
            }
        )
        
    except Exception as e:
        logger.error(f"Error setting up streaming for {request.domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


async def _generate_attack_paths_stream(request: AttackPathRequest) -> AsyncGenerator[str, None]:
    """Generate streaming response for attack paths"""
    try:
        # Progress callback function
        async def progress_callback(update: StreamingPathUpdate):
            global streaming_updates
            streaming_updates.append(update)
            # Send the update as a server-sent event
            yield f"data: {update.json()}\n\n"
        
        # Generate attack paths with streaming
        response = await attack_path_service.generate_attack_paths(
            domain=request.domain,
            top_n=request.top_n or settings.DEFAULT_TOP_N,
            progress_callback=progress_callback
        )
        
        # Send final response
        final_data = {
            "type": "final_response",
            "data": response.dict()
        }
        yield f"data: {json.dumps(final_data)}\n\n"
        
        # Send end marker
        yield "data: [DONE]\n\n"
        
    except Exception as e:
        logger.error(f"Error in streaming generation: {e}")
        error_data = {
            "type": "error",
            "message": str(e)
        }
        yield f"data: {json.dumps(error_data)}\n\n"


@app.get("/api/v1/attack-paths/stream/updates")
async def get_streaming_updates():
    """Get all streaming updates for debugging"""
    return {
        "updates": streaming_updates,
        "count": len(streaming_updates)
    }


@app.get("/api/v1/attack-paths/{domain}/summary", response_class=HTMLResponse)
async def get_attack_paths_summary(domain: str, top_n: int = 10):
    """Get HTML summary of attack paths for a domain"""
    try:
        # Generate attack paths
        response = await attack_path_service.generate_attack_paths(
            domain=domain,
            top_n=top_n
        )
        
        # Generate HTML summary
        html_content = _generate_html_summary(response)
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        logger.error(f"Error generating HTML summary for {domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


def _generate_html_summary(response: AttackPathResponse) -> str:
    """Generate HTML summary of attack paths"""
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Attack Path Summary - {response.domain}</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #e0e0e0;
            }}
            .header h1 {{
                color: #2c3e50;
                margin-bottom: 10px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                border-left: 4px solid #007bff;
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                color: #007bff;
            }}
            .stat-label {{
                color: #6c757d;
                font-size: 0.9em;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            .path-card {{
                background-color: #f8f9fa;
                margin-bottom: 20px;
                border-radius: 8px;
                overflow: hidden;
                border: 1px solid #e0e0e0;
            }}
            .path-header {{
                background-color: #007bff;
                color: white;
                padding: 15px 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .path-name {{
                font-size: 1.2em;
                font-weight: bold;
            }}
            .risk-score {{
                background-color: rgba(255,255,255,0.2);
                padding: 5px 15px;
                border-radius: 20px;
                font-weight: bold;
            }}
            .path-content {{
                padding: 20px;
            }}
            .path-description {{
                color: #6c757d;
                margin-bottom: 15px;
            }}
            .path-details {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }}
            .detail-item {{
                background-color: white;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #e0e0e0;
            }}
            .detail-label {{
                font-weight: bold;
                color: #495057;
                margin-bottom: 5px;
                text-transform: uppercase;
                font-size: 0.8em;
                letter-spacing: 1px;
            }}
            .detail-value {{
                color: #212529;
            }}
            .attack-steps {{
                background-color: white;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #e0e0e0;
            }}
            .attack-steps h4 {{
                margin-top: 0;
                color: #495057;
                border-bottom: 1px solid #e0e0e0;
                padding-bottom: 10px;
            }}
            .step-list {{
                list-style-type: none;
                padding: 0;
            }}
            .step-list li {{
                padding: 8px 0;
                border-bottom: 1px solid #f0f0f0;
                position: relative;
                padding-left: 25px;
            }}
            .step-list li:before {{
                content: "→";
                position: absolute;
                left: 0;
                color: #007bff;
                font-weight: bold;
            }}
            .step-list li:last-child {{
                border-bottom: none;
            }}
            .rationale {{
                background-color: white;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #e0e0e0;
                margin-top: 15px;
            }}
            .rationale h4 {{
                margin-top: 0;
                color: #495057;
                border-bottom: 1px solid #e0e0e0;
                padding-bottom: 10px;
            }}
            .footer {{
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e0e0e0;
                color: #6c757d;
                font-size: 0.9em;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🚨 Attack Path Analysis Report</h1>
                <p><strong>Domain:</strong> {response.domain} | <strong>Generated:</strong> {response.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{response.total_paths_found}</div>
                    <div class="stat-label">Total Paths Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(response.top_paths)}</div>
                    <div class="stat-label">Top Paths Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{response.processing_time_seconds:.1f}s</div>
                    <div class="stat-label">Processing Time</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{response.organization_id}</div>
                    <div class="stat-label">Organization ID</div>
                </div>
            </div>
    """
    
    if not response.top_paths:
        html += """
            <div class="path-card">
                <div class="path-header">
                    <span class="path-name">No Attack Paths Found</span>
                </div>
                <div class="path-content">
                    <p>No attack paths were identified for this organization based on the current data and templates.</p>
                </div>
            </div>
        """
    else:
        for i, path in enumerate(response.top_paths, 1):
            # Determine risk color based on score
            risk_color = "#dc3545" if path.risk_score >= 0.8 else "#fd7e14" if path.risk_score >= 0.6 else "#ffc107" if path.risk_score >= 0.4 else "#28a745"
            
            html += f"""
            <div class="path-card">
                <div class="path-header">
                    <span class="path-name">#{i}: {path.path_name}</span>
                    <span class="risk-score" style="background-color: {risk_color};">Risk: {path.risk_score:.2f}</span>
                </div>
                <div class="path-content">
                    <div class="path-description">{path.path_description}</div>
                    
                    <div class="path-details">
                        <div class="detail-item">
                            <div class="detail-label">Goals</div>
                            <div class="detail-value">{', '.join(path.goals)}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Likelihood</div>
                            <div class="detail-value">{path.likelihood_score:.2f}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Impact</div>
                            <div class="detail-value">{path.impact_score:.2f}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Confidence</div>
                            <div class="detail-value">{path.confidence_level}</div>
                        </div>
                    </div>
                    
                    <div class="attack-steps">
                        <h4>🎯 Attack Steps</h4>
                        <ol class="step-list">
            """
            
            for step in path.attack_steps:
                html += f"<li>{step}</li>"
            
            html += """
                        </ol>
                    </div>
                    
                    <div class="rationale">
                        <h4>💭 Analysis Rationale</h4>
                        <p>{path.rationale}</p>
                    </div>
                </div>
            </div>
            """
    
    html += f"""
            <div class="footer">
                <p>Report generated by Attack Path Generation LLM Agent | Scan ID: {response.scan_id}</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html


@app.get("/api/v1/attack-paths/{domain}/markdown")
async def get_attack_paths_markdown(domain: str, top_n: int = 10):
    """Get Markdown summary of attack paths for a domain"""
    try:
        # Generate attack paths
        response = await attack_path_service.generate_attack_paths(
            domain=domain,
            top_n=top_n
        )
        
        # Generate Markdown summary
        markdown_content = _generate_markdown_summary(response)
        return {"markdown": markdown_content}
        
    except Exception as e:
        logger.error(f"Error generating Markdown summary for {domain}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


def _generate_markdown_summary(response: AttackPathResponse) -> str:
    """Generate Markdown summary of attack paths"""
    markdown = f"""# 🚨 Attack Path Analysis Report

**Domain:** {response.domain}  
**Generated:** {response.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  
**Organization ID:** {response.organization_id}  
**Scan ID:** {response.scan_id}

## 📊 Summary Statistics

- **Total Paths Found:** {response.total_paths_found}
- **Top Paths Analyzed:** {len(response.top_paths)}
- **Processing Time:** {response.processing_time_seconds:.1f}s

---

"""
    
    if not response.top_paths:
        markdown += """
## ❌ No Attack Paths Found

No attack paths were identified for this organization based on the current data and templates.
"""
    else:
        for i, path in enumerate(response.top_paths, 1):
            # Determine risk level based on score
            risk_level = "🔴 CRITICAL" if path.risk_score >= 0.8 else "🟠 HIGH" if path.risk_score >= 0.6 else "🟡 MEDIUM" if path.risk_score >= 0.4 else "🟢 LOW"
            
            markdown += f"""
## #{i}: {path.path_name}

**Risk Score:** {path.risk_score:.2f} {risk_level}  
**Likelihood:** {path.likelihood_score:.2f}  
**Impact:** {path.impact_score:.2f}  
**Confidence:** {path.confidence_level}

### Description
{path.path_description}

### Goals
{', '.join(path.goals)}

### 🎯 Attack Steps
"""
            
            for j, step in enumerate(path.attack_steps, 1):
                markdown += f"{j}. {step}\n"
            
            markdown += f"""
### 💭 Analysis Rationale
{path.rationale}

---

"""
    
    markdown += f"""
*Report generated by Attack Path Generation LLM Agent*
"""
    
    return markdown


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 