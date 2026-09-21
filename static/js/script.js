document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-custom-select]').forEach(function (container) {
    const select = container.querySelector('select');
    const trigger = container.querySelector('.custom-select__trigger');
    const value = container.querySelector('.custom-select__value');
    const menu = container.querySelector('.custom-select__menu');

    function closeMenu() {
      container.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
    }

    function updateSelection() {
      const selected = select.options[select.selectedIndex];
      value.textContent = selected ? selected.textContent : 'choose a question';
      menu.querySelectorAll('.custom-select__option').forEach(function (option) {
        option.classList.toggle('is-selected', option.dataset.value === select.value);
        option.setAttribute('aria-selected', option.dataset.value === select.value ? 'true' : 'false');
      });
    }

    Array.from(select.options).filter(function (option) {
      return option.value;
    }).forEach(function (option, index) {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'custom-select__option';
      item.dataset.value = option.value;
      item.setAttribute('role', 'option');
      item.innerHTML = '<span class="custom-select__option-mark">' + (index + 1) + '</span><span>' + option.textContent + '</span>';
      item.addEventListener('click', function () {
        select.value = option.value;
        select.dispatchEvent(new Event('change', { bubbles: true }));
        closeMenu();
        trigger.focus();
      });
      menu.appendChild(item);
    });

    trigger.addEventListener('click', function () {
      const willOpen = !container.classList.contains('is-open');
      document.querySelectorAll('[data-custom-select].is-open').forEach(function (openSelect) {
        openSelect.classList.remove('is-open');
        openSelect.querySelector('.custom-select__trigger').setAttribute('aria-expanded', 'false');
      });
      container.classList.toggle('is-open', willOpen);
      trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    });

    trigger.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        closeMenu();
      }
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        container.classList.add('is-open');
        trigger.setAttribute('aria-expanded', 'true');
        const options = Array.from(menu.querySelectorAll('.custom-select__option'));
        const currentIndex = options.findIndex(function (option) {
          return option.dataset.value === select.value;
        });
        const targetIndex = event.key === 'ArrowDown'
          ? Math.min(currentIndex + 1, options.length - 1)
          : Math.max(currentIndex - 1, 0);
        options[targetIndex >= 0 ? targetIndex : 0].focus();
      }
    });

    menu.addEventListener('keydown', function (event) {
      const options = Array.from(menu.querySelectorAll('.custom-select__option'));
      const currentIndex = options.indexOf(document.activeElement);
      if (event.key === 'Escape') {
        closeMenu();
        trigger.focus();
      }
      if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && currentIndex >= 0) {
        event.preventDefault();
        const nextIndex = event.key === 'ArrowDown'
          ? Math.min(currentIndex + 1, options.length - 1)
          : Math.max(currentIndex - 1, 0);
        options[nextIndex].focus();
      }
    });

    select.addEventListener('change', updateSelection);
    select.addEventListener('invalid', function () {
      trigger.focus();
    });
    updateSelection();
  });

  document.addEventListener('click', function (event) {
    document.querySelectorAll('[data-custom-select].is-open').forEach(function (container) {
      if (!container.contains(event.target)) {
        container.classList.remove('is-open');
        container.querySelector('.custom-select__trigger').setAttribute('aria-expanded', 'false');
      }
    });
  });
});
