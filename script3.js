document.addEventListener('DOMContentLoaded', () => {
    const newConversationBtn = document.querySelector('.new-conversation');
    const conversationList = document.querySelector('.conversation-list');
    const messageInput = document.querySelector('.input-area input');
    const sendButton = document.querySelector('.input-area button');
    const messagesContainer = document.querySelector('.messages');
    const webAccessToggle = document.querySelector('input[type="checkbox"]');
    const darkModeToggle = document.querySelectorAll('input[type="checkbox"]')[1];
    const menuToggle = document.querySelector('.menu-toggle');
    const mobileMenu = document.querySelector('.mobile-menu');
    const exploreForm = document.querySelector('.email-signup');
    const exploreButton = document.getElementById('exploreButton');

    // Set initial mode
    document.body.classList.toggle('dark-mode', darkModeToggle.checked);

    // New Conversation button
    newConversationBtn.addEventListener('click', () => {
        const newConversation = document.createElement('div');
        newConversation.className = 'conversation';
        newConversation.textContent = 'New Conversation';
        conversationList.appendChild(newConversation);
        
        // Add click event to the new conversation
        newConversation.addEventListener('click', () => {
            console.log('Conversation clicked:', newConversation.textContent);
            // Add functionality for switching to this conversation
        });
    });

    // Send message function
    function sendMessage() {
        const message = messageInput.value.trim();
        if (message) {
            const userMessage = createMessage('user', message);
            messagesContainer.appendChild(userMessage);
            messageInput.value = '';

            // Detect language and respond
            const detectedLanguage = detectLanguage(message);
            const response = `Detected language: ${detectedLanguage}\n\nHere's a sample response for ${detectedLanguage} code:\n\n${generateSampleResponse(detectedLanguage)}`;
            
            setTimeout(() => {
                const botMessage = createMessage('bot', response);
                messagesContainer.appendChild(botMessage);
            }, 1000);
        }
    }

    // Send button
    sendButton.addEventListener('click', sendMessage);

    // Enter key in input
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    // Create message element
    function createMessage(type, content) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        
        const avatar = document.createElement('div');
        avatar.className = 'avatar';
        avatar.textContent = type === 'user' ? '👤' : '🤖';
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'content';
        contentDiv.innerHTML = content.replace(/\n/g, '<br>');
        
        messageDiv.appendChild(avatar);
        messageDiv.appendChild(contentDiv);
        
        return messageDiv;
    }

    // Web Access toggle
    webAccessToggle.addEventListener('change', (e) => {
        console.log('Web Access:', e.target.checked ? 'Enabled' : 'Disabled');
        // Implement web access functionality here
    });

    // Dark Mode toggle
    darkModeToggle.addEventListener('change', (e) => {
        document.body.classList.toggle('dark-mode', e.target.checked);
    });

    // Simple language detection function
    function detectLanguage(code) {
        if (code.includes('print(') || code.includes('def ')) return 'Python';
        if (code.includes('console.log(') || code.includes('function ')) return 'JavaScript';
        if (code.includes('System.out.println(') || code.includes('public class ')) return 'Java';
        if (code.includes('cout <<') || code.includes('#include')) return 'C++';
        if (code.includes('fmt.Println(') || code.includes('func ')) return 'Go';
        if (code.includes('puts ') || code.includes('def ')) return 'Ruby';
        if (code.includes('echo ') || code.includes('<?php')) return 'PHP';
        return 'Unknown';
    }

    // Generate a sample response based on detected language
    function generateSampleResponse(language) {
        switch (language) {
            case 'Python':
                return 'def greet(name):\n    print(f"Hello, {name}!")';
            case 'JavaScript':
                return 'function greet(name) {\n    console.log(`Hello, ${name}!`);\n}';
            case 'Java':
                return 'public class Greeting {\n    public static void greet(String name) {\n        System.out.println("Hello, " + name + "!");\n    }\n}';
            case 'C++':
                return '#include <iostream>\n\nvoid greet(std::string name) {\n    std::cout << "Hello, " << name << "!" << std::endl;\n}';
            case 'Go':
                return 'func greet(name string) {\n    fmt.Printf("Hello, %s!\\n", name)\n}';
            case 'Ruby':
                return 'def greet(name)\n    puts "Hello, #{name}!"\nend';
            case 'PHP':
                return '<?php\nfunction greet($name) {\n    echo "Hello, " . $name . "!";\n}\n?>';
            default:
                return 'Sorry, I couldn\'t generate a sample for the detected language.';
        }
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();

            const href = this.getAttribute('href');
            const targetElement = document.querySelector(href);

            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    menuToggle.addEventListener('click', () => {
        mobileMenu.classList.toggle('active');
    });

    // Smooth scrolling for navigation links
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            
            if (href === '/') {
                // Reload the page for the Home link
                window.location.reload();
            } else if (href.startsWith('#')) {
                e.preventDefault();
                const targetElement = document.querySelector(href);
                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
            // Note: We don't need to handle the 'Explore' link here as it's a regular link now
        });
    });

    var lazyImages = [].slice.call(document.querySelectorAll("img.lazy"));

    if ("IntersectionObserver" in window) {
        let lazyImageObserver = new IntersectionObserver(function(entries, observer) {
            entries.forEach(function(entry) {
                if (entry.isIntersecting) {
                    let lazyImage = entry.target;
                    lazyImage.src = lazyImage.dataset.src;
                    lazyImage.classList.remove("lazy");
                    lazyImageObserver.unobserve(lazyImage);
                }
            });
        });

        lazyImages.forEach(function(lazyImage) {
            lazyImageObserver.observe(lazyImage);
        });
    }

    function reveal() {
        var reveals = document.querySelectorAll(".reveal");
        for (var i = 0; i < reveals.length; i++) {
            var windowHeight = window.innerHeight;
            var elementTop = reveals[i].getBoundingClientRect().top;
            var elementVisible = 150;
            if (elementTop < windowHeight - elementVisible) {
                reveals[i].classList.add("active");
            } else {
                reveals[i].classList.remove("active");
            }
        }
    }

    window.addEventListener("scroll", reveal);

    // Smooth scroll function
    function smoothScroll(target) {
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset;
        const startPosition = window.pageYOffset;
        const distance = targetPosition - startPosition;
        const duration = 1000; // Changed to 4000ms (4 seconds)
        let start = null;

        function animation(currentTime) {
            if (start === null) start = currentTime;
            const timeElapsed = currentTime - start;
            const run = ease(timeElapsed, startPosition, distance, duration);
            window.scrollTo(0, run);
            if (timeElapsed < duration) requestAnimationFrame(animation);
        }

        // Easing function
        function ease(t, b, c, d) {
            t /= d / 2;
            if (t < 1) return c / 2 * t * t + b;
            t--;
            return -c / 2 * (t * (t - 2) - 1) + b;
        }

        requestAnimationFrame(animation);
    }
});
