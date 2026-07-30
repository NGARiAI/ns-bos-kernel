"""
NS BOS Kernel - Agent Runtime Framework
Agent lifecycle management, inter-agent communication, task scheduling,
and memory/state management.
"""

import os
import json
import time
import uuid
import asyncio
import logging
from datetime import datetime
from typing import Optional, Any, Callable, Dict, List
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class AgentStateEnum(Enum):
    INITIALIZING = "initializing"
    RUNNING = "running"
    IDLE = "idle"
    PAUSED = "paused"
    ERROR = "error"
    TERMINATED = "terminated"


class TaskPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class AgentConfig:
    name: str
    agent_type: str
    version: str = "1.0.0"
    description: str = ""
    max_memory_mb: int = 512
    restart_on_failure: bool = True
    max_restarts: int = 5
    environment: dict = field(default_factory=dict)


@dataclass
class Task:
    task_id: str
    agent_id: str
    action: str
    payload: dict
    priority: TaskPriority = TaskPriority.NORMAL
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Any] = None
    error: Optional[str] = None


@dataclass
class AgentState:
    agent_id: str
    config: AgentConfig
    state: AgentStateEnum = AgentStateEnum.INITIALIZING
    memory: dict = field(default_factory=dict)
    tasks_completed: int = 0
    tasks_failed: int = 0
    uptime_seconds: float = 0
    last_heartbeat: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error_count: int = 0


class AgentRegistry:
    """Registry for managing agent configurations and state"""

    def __init__(self, registry_dir: str = None):
        registry_dir = registry_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel" / "agents" / "registry"))
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.agents: Dict[str, AgentState] = {}
        self._load_registry()

    def _load_registry(self):
        """Load agent registry from disk"""
        registry_file = self.registry_dir / "registry.json"
        if registry_file.exists():
            with open(registry_file, "r") as f:
                data = json.load(f)
                for agent_id, agent_data in data.items():
                    config = AgentConfig(**agent_data["config"])
                    self.agents[agent_id] = AgentState(
                        agent_id=agent_id,
                        config=config,
                        state=AgentStateEnum(agent_data.get("state", "initializing")),
                        memory=agent_data.get("memory", {}),
                        tasks_completed=agent_data.get("tasks_completed", 0),
                        tasks_failed=agent_data.get("tasks_failed", 0),
                        uptime_seconds=agent_data.get("uptime_seconds", 0),
                        last_heartbeat=agent_data.get("last_heartbeat", datetime.utcnow().isoformat()),
                        started_at=agent_data.get("started_at", datetime.utcnow().isoformat()),
                        error_count=agent_data.get("error_count", 0)
                    )

    def save_registry(self):
        """Save agent registry to disk"""
        data = {}
        for agent_id, state in self.agents.items():
            data[agent_id] = {
                "config": asdict(state.config),
                "state": state.state.value,
                "memory": state.memory,
                "tasks_completed": state.tasks_completed,
                "tasks_failed": state.tasks_failed,
                "uptime_seconds": state.uptime_seconds,
                "last_heartbeat": state.last_heartbeat,
                "started_at": state.started_at,
                "error_count": state.error_count
            }

        registry_file = self.registry_dir / "registry.json"
        with open(registry_file, "w") as f:
            json.dump(data, f, indent=2)

    def register_agent(self, config: AgentConfig) -> str:
        """Register a new agent"""
        agent_id = str(uuid.uuid4())
        state = AgentState(agent_id=agent_id, config=config)
        self.agents[agent_id] = state
        self.save_registry()
        logger.info(f"Agent registered: {config.name} ({agent_id})")
        return agent_id

    def get_agent(self, agent_id: str) -> Optional[AgentState]:
        """Get agent state by ID"""
        return self.agents.get(agent_id)

    def list_agents(self) -> List[AgentState]:
        """List all registered agents"""
        return list(self.agents.values())

    def update_agent_state(self, agent_id: str, state: AgentStateEnum):
        """Update agent state"""
        if agent_id in self.agents:
            self.agents[agent_id].state = state
            self.agents[agent_id].last_heartbeat = datetime.utcnow().isoformat()
            self.save_registry()


class TaskScheduler:
    """Task scheduler with priority queue"""

    def __init__(self, scheduler_dir: str = None):
        scheduler_dir = scheduler_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel" / "tasks"))
        self.scheduler_dir = Path(scheduler_dir)
        self.scheduler_dir.mkdir(parents=True, exist_ok=True)
        self.tasks: Dict[str, Task] = {}
        self.handlers: Dict[str, Callable] = {}
        self._load_tasks()

    def _load_tasks(self):
        """Load tasks from disk"""
        tasks_file = self.scheduler_dir / "tasks.json"
        if tasks_file.exists():
            with open(tasks_file, "r") as f:
                data = json.load(f)
                for task_id, task_data in data.items():
                    self.tasks[task_id] = Task(**task_data)

    def save_tasks(self):
        """Save tasks to disk"""
        data = {}
        for task_id, task in self.tasks.items():
            data[task_id] = asdict(task)

        tasks_file = self.scheduler_dir / "tasks.json"
        with open(tasks_file, "w") as f:
            json.dump(data, f, indent=2)

    def register_handler(self, action: str, handler: Callable):
        """Register a task handler"""
        self.handlers[action] = handler

    def create_task(self, agent_id: str, action: str, payload: dict,
                    priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """Create a new task"""
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            agent_id=agent_id,
            action=action,
            payload=payload,
            priority=priority
        )
        self.tasks[task_id] = task
        self.save_tasks()
        logger.info(f"Task created: {task_id} - {action} (priority: {priority.name})")
        return task_id

    def get_pending_tasks(self) -> List[Task]:
        """Get pending tasks sorted by priority"""
        pending = [t for t in self.tasks.values() if t.status == "pending"]
        return sorted(pending, key=lambda t: t.priority.value, reverse=True)

    async def execute_task(self, task: Task) -> Any:
        """Execute a task"""
        if task.action not in self.handlers:
            task.status = "error"
            task.error = f"No handler registered for action: {task.action}"
            self.save_tasks()
            return None

        task.status = "running"
        task.started_at = datetime.utcnow().isoformat()
        self.save_tasks()

        try:
            handler = self.handlers[task.action]
            result = handler(task.payload)
            if asyncio.iscoroutine(result):
                result = await result

            task.status = "completed"
            task.completed_at = datetime.utcnow().isoformat()
            task.result = result
            self.save_tasks()
            return result
        except Exception as e:
            task.status = "error"
            task.error = str(e)
            task.completed_at = datetime.utcnow().isoformat()
            self.save_tasks()
            logger.error(f"Task {task.task_id} failed: {e}")
            return None

    async def process_queue(self):
        """Process all pending tasks"""
        pending = self.get_pending_tasks()
        results = []
        for task in pending:
            result = await self.execute_task(task)
            results.append(result)
        return results


class InterAgentCommunication:
    """Inter-agent message bus"""

    def __init__(self, comm_dir: str = None):
        comm_dir = comm_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel" / "comm"))
        self.comm_dir = Path(comm_dir)
        self.comm_dir.mkdir(parents=True, exist_ok=True)
        self.subscribers: Dict[str, List[Callable]] = {}

    def publish(self, topic: str, message: dict):
        """Publish a message to a topic"""
        message_file = self.comm_dir / f"{topic}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        message_data = {
            "topic": topic,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        with open(message_file, "w") as f:
            json.dump(message_data, f, indent=2)

        # Notify subscribers
        if topic in self.subscribers:
            for callback in self.subscribers[topic]:
                try:
                    callback(message)
                except Exception as e:
                    logger.error(f"Subscriber callback failed: {e}")

    def subscribe(self, topic: str, callback: Callable):
        """Subscribe to a topic"""
        if topic not in self.subscribers:
            self.subscribers[topic] = []
        self.subscribers[topic].append(callback)

    def get_messages(self, topic: str, limit: int = 10) -> List[dict]:
        """Get recent messages for a topic"""
        messages = []
        for file in sorted(self.comm_dir.glob(f"{topic}_*.json"), reverse=True)[:limit]:
            with open(file, "r") as f:
                messages.append(json.load(f))
        return messages


class AgentRuntime:
    """
    Main agent runtime - orchestrates agent lifecycle, task scheduling,
    and inter-agent communication.
    """

    def __init__(self, data_dir: str = None):
        data_dir = data_dir or os.environ.get("NGARI_DATA_DIR", str(Path.home() / ".ngari" / "kernel"))
        self.registry = AgentRegistry(os.path.join(data_dir, "registry"))
        self.scheduler = TaskScheduler(os.path.join(data_dir, "tasks"))
        self.comm = InterAgentCommunication(os.path.join(data_dir, "comm"))
        self.running = False

    def start(self):
        """Start the agent runtime"""
        self.running = True
        logger.info("Agent Runtime started")

        # Update all agent states to running
        for agent in self.registry.list_agents():
            if agent.state == AgentStateEnum.INITIALIZING:
                agent.state = AgentStateEnum.RUNNING
                self.registry.update_agent_state(agent.agent_id, agent.state)

    def stop(self):
        """Stop the agent runtime"""
        self.running = False
        logger.info("Agent Runtime stopped")

    def register_agent(self, config: AgentConfig) -> str:
        """Register a new agent"""
        return self.registry.register_agent(config)

    def create_task(self, agent_id: str, action: str, payload: dict,
                    priority: TaskPriority = TaskPriority.NORMAL) -> str:
        """Create a new task for an agent"""
        return self.scheduler.create_task(agent_id, action, payload, priority)

    def publish_event(self, topic: str, message: dict):
        """Publish an inter-agent event"""
        self.comm.publish(topic, message)

    def subscribe_event(self, topic: str, callback: Callable):
        """Subscribe to an inter-agent event"""
        self.comm.subscribe(topic, callback)

    def get_status(self) -> dict:
        """Get runtime status"""
        agents = self.registry.list_agents()
        from . import AgentStateEnum
        states = {}
        for s in AgentStateEnum:
            states[s.value] = 0
        for a in agents:
            key = a.state.value if hasattr(a.state, 'value') else str(a.state)
            states[key] = states.get(key, 0) + 1
        return {
            "running": self.running,
            "agents": len(agents),
            "agents_by_state": states,
            "pending_tasks": len(self.scheduler.get_pending_tasks()),
            "total_tasks": len(self.scheduler.tasks)
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    runtime = AgentRuntime()
    runtime.start()

    # Register a test agent
    config = AgentConfig(
        name="TestAgent",
        agent_type="test",
        description="Test agent for NS BOS kernel"
    )
    agent_id = runtime.register_agent(config)

    # Register a task handler
    def test_handler(payload):
        return f"Processed: {payload}"

    runtime.scheduler.register_handler("test_action", test_handler)

    # Create and execute a task
    task_id = runtime.create_task(agent_id, "test_action", {"data": "hello"})

    # Publish an event
    runtime.publish_event("agent_status", {"agent_id": agent_id, "status": "running"})

    # Get status
    status = runtime.get_status()
    print(f"Runtime status: {json.dumps(status, indent=2)}")

    runtime.stop()
