from locust import HttpUser, task, between

class ProjectUser(HttpUser):
    # Wait time between each task execution in seconds
    wait_time = between(1, 5)

    @task
    def get_root(self):
        """Simulates a user visiting the root/home page."""
        self.client.get("/")

    # You can add more tasks here to simulate other user behaviors.
    # For example, if you have an API endpoint at /api/threats:
    #
    # @task(3)  # This task will be 3 times more likely to be chosen
    # def get_threats(self):
    #     self.client.get("/api/threats")
