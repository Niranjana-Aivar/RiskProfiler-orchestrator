#!/usr/bin/env python3
"""
Monitor Bedrock throttling health and metrics in production
"""

import asyncio
import json
import time
from datetime import datetime
from llm_scoring_service import llm_scoring_service, production_throttling


async def monitor_throttling_health():
    """Monitor and display throttling health metrics"""
    
    print("🔍 Bedrock Throttling Health Monitor")
    print("=" * 50)
    
    try:
        # Initialize LLM service
        await llm_scoring_service.initialize()
        
        # Get comprehensive health status
        health_status = llm_scoring_service.get_throttling_health_status()
        
        print(f"📊 Health Status Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        # Circuit Breaker Status
        cb_state = health_status.get('circuit_breaker_state', 'unknown')
        cb_emoji = {
            'closed': '✅',
            'open': '🔴', 
            'half_open': '🟡',
            'unknown': '❓'
        }.get(cb_state, '❓')
        
        print(f"{cb_emoji} Circuit Breaker: {cb_state.upper()}")
        
        # Key Metrics
        metrics = health_status.get('metrics', {})
        print(f"📈 Success Rate: {metrics.get('success_rate', 0)}%")
        print(f"🚦 Throttle Rate: {metrics.get('throttle_rate', 0)}%")
        print(f"🔄 Total Requests: {metrics.get('total_requests', 0)}")
        print(f"⚡ Circuit Breaker Trips: {metrics.get('circuit_breaker_trips', 0)}")
        print(f"⏱️  Average Retry Time: {metrics.get('avg_retry_time', 0)}s")
        print(f"⏰ Max Retry Time: {metrics.get('max_retry_time', 0)}s")
        
        # Current State
        current_delay = health_status.get('current_delay', 0)
        if current_delay > 0:
            print(f"🐌 Current Adaptive Delay: {current_delay:.2f}s")
        else:
            print("🚀 No Current Delay - Running at Full Speed")
            
        # Dead Letter Queue
        dlq_size = health_status.get('dead_letter_queue_size', 0)
        if dlq_size > 0:
            print(f"💀 Dead Letter Queue: {dlq_size} failed requests")
        else:
            print("✅ Dead Letter Queue: Empty")
        
        # Last Throttle Event
        last_throttle = health_status.get('last_throttle')
        if last_throttle:
            throttle_ago = time.time() - last_throttle
            print(f"🕒 Last Throttle: {throttle_ago:.1f}s ago")
        else:
            print("🎉 No Recent Throttling")
            
        # Model Configuration
        print(f"\n🤖 Model Configuration:")
        print(f"   Model: {health_status.get('llm_model', 'unknown')}")
        print(f"   Temperature: {health_status.get('temperature', 'unknown')}")
        print(f"   Max Tokens: {health_status.get('max_tokens', 'unknown')}")
        
        # Failed Requests Analysis
        failed_requests = llm_scoring_service.get_failed_requests_analysis(5)
        if failed_requests:
            print(f"\n💥 Recent Failed Requests ({len(failed_requests)}):")
            for req in failed_requests:
                timestamp = datetime.fromtimestamp(req['timestamp']).strftime('%H:%M:%S')
                print(f"   {timestamp} - {req['operation_id']}: {req['error'][:100]}...")
        
        # Health Assessment
        print(f"\n🏥 Overall Health Assessment:")
        success_rate = metrics.get('success_rate', 0)
        throttle_rate = metrics.get('throttle_rate', 0)
        
        if success_rate >= 95 and throttle_rate < 5:
            print("✅ HEALTHY - Excellent performance")
        elif success_rate >= 85 and throttle_rate < 15:
            print("🟡 DEGRADED - Some throttling, monitor closely")
        elif success_rate >= 70:
            print("🟠 POOR - High throttling, consider scaling down")
        else:
            print("🔴 CRITICAL - Very low success rate, immediate action needed")
            
        # Recommendations
        if throttle_rate > 20:
            print("\n💡 Recommendations:")
            print("   - Reduce concurrent requests")
            print("   - Increase delays between requests")
            print("   - Consider request quotas increase")
            
        if cb_state == 'open':
            print("\n🚨 Circuit Breaker is OPEN!")
            print("   - All requests are being rejected")
            print("   - Wait for automatic recovery or manual reset")
            print("   - Consider: llm_scoring_service.reset_throttling_circuit_breaker()")
            
    except Exception as e:
        print(f"❌ Error monitoring throttling health: {e}")


async def test_throttling_resilience():
    """Test the throttling resilience with a series of requests"""
    
    print("\n🧪 Testing Throttling Resilience")
    print("=" * 50)
    
    test_prompts = [
        "Simple test prompt 1",
        "Simple test prompt 2", 
        "Simple test prompt 3"
    ]
    
    results = []
    
    for i, prompt in enumerate(test_prompts, 1):
        try:
            print(f"📤 Test {i}/3: Sending request...")
            start_time = time.time()
            
            response = await llm_scoring_service._call_bedrock_api(f"Test prompt: {prompt}")
            
            elapsed = time.time() - start_time
            print(f"✅ Test {i}: Success in {elapsed:.2f}s")
            results.append({'test': i, 'success': True, 'time': elapsed})
            
        except Exception as e:
            elapsed = time.time() - start_time
            print(f"❌ Test {i}: Failed in {elapsed:.2f}s - {e}")
            results.append({'test': i, 'success': False, 'time': elapsed, 'error': str(e)})
    
    # Summary
    successful = sum(1 for r in results if r['success'])
    print(f"\n📊 Test Results: {successful}/{len(results)} successful")
    
    if successful == len(results):
        print("🎉 All tests passed - throttling is working correctly!")
    else:
        print("⚠️  Some tests failed - check throttling configuration")


def display_circuit_breaker_commands():
    """Display useful circuit breaker management commands"""
    
    print("\n🔧 Circuit Breaker Management Commands:")
    print("-" * 40)
    print("# Check health status")
    print("health = llm_scoring_service.get_throttling_health_status()")
    print("print(json.dumps(health, indent=2))")
    print()
    print("# Reset circuit breaker manually")
    print("llm_scoring_service.reset_throttling_circuit_breaker()")
    print()
    print("# Get failed requests for analysis")
    print("failures = llm_scoring_service.get_failed_requests_analysis(10)")
    print("for failure in failures:")
    print("    print(f\"{failure['timestamp']}: {failure['error']}\")")


async def main():
    """Main monitoring function"""
    
    # Monitor current health
    await monitor_throttling_health()
    
    # Test resilience
    await test_throttling_resilience()
    
    # Show management commands
    display_circuit_breaker_commands()
    
    print(f"\n🔄 Run this script periodically to monitor Bedrock throttling health!")


if __name__ == "__main__":
    asyncio.run(main())
